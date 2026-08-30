#!/usr/bin/env bash
# Read-only triage for "SSH to this server is fast, SFTP to the same server is slow".
#
# The case it was written for: an interactive shell on a VPS (a Linode, typically)
# feels instant, and a file transfer over the very same SSH connection crawls. That
# shape rules a lot out immediately — the port is open, the key works, the route is
# up, the ciphers are agreed — and it leaves a short list of specific causes.
#
# The two complaints hiding inside "sftp is slow" fail differently, so the script
# separates them and answers both:
#
#   A) slow to CONNECT — seconds of nothing, then a prompt, then normal speed.
#      That is name resolution or authentication, not throughput.  -> section 6
#   B) slow to TRANSFER — connects at once, bytes crawl.
#      That is per-packet cost, loss/MTU, CPU, or the SFTP protocol's own window.
#      -> sections 1-5 and 7
#
# The reason interactive SSH stays fast under B is arithmetic, not luck: a shell
# session is a few dozen small packets a second, so anything that costs per packet
# or drops one in a hundred is invisible in it, and ruinous in a transfer moving
# tens of thousands of packets a second.
#
# It also checks the thing this app can do to your own transfer: an SFTP DOWNLOAD
# is outbound traffic from this server to one address, which is exactly what the
# exfiltration monitor watches for. 250 MB in 10 minutes is a High threat by
# default, and High is the default auto-block level.
#
# Changes nothing. Every command here only reads state, so it is safe on a
# production node and safe to run repeatedly. Best run WHILE a slow transfer is in
# flight — sections 1, 3 and 4 read live per-socket kernel counters.
#
# Usage:
#   sudo bash scripts/diagnose-sftp-slowness.sh              # client IP from $SSH_CONNECTION
#   sudo bash scripts/diagnose-sftp-slowness.sh 203.0.113.9  # or name it
#
# Secrets: prints no keys, no password hashes, and nothing from settings.json
# beyond the named auto-block and exfiltration keys.

set -u

say()     { printf '\n=== %s ===\n' "$1"; }
info()    { printf '  %s\n' "$*"; }
verdict() { printf -- '--> %s\n' "$*"; }
have()    { command -v "$1" >/dev/null 2>&1; }

# Join two captured blocks, dropping blank lines, so appending an iptables result
# to an nft one cannot glue two findings onto a single line.
addlines() { printf '%s\n%s\n' "${1:-}" "${2:-}" | grep -v '^[[:space:]]*$'; }

# Print a captured block indented, or the given "nothing found" line. Keeps every
# lookup below to ONE execution — some of these list the whole ruleset.
block()   {
    if [ -n "${1:-}" ]; then printf '%s\n' "$1" | sed 's/^/    /'; return 0
    else printf '    %s\n' "${2:-(none)}"; return 1; fi
}

if [ "$(id -u)" -ne 0 ]; then
    echo "Run with sudo — firewall rules, per-socket counters, sshd config and the"
    echo "app's threat log are all root-readable only."
    echo "  sudo bash $0 $*"
    exit 1
fi

# Whose transfer is slow. The argument wins; otherwise the address of the session
# running this script, which is the right answer often enough to be the default.
CLIENT_IP="${1:-}"
if [ -z "$CLIENT_IP" ] && [ -n "${SSH_CONNECTION:-}" ]; then
    CLIENT_IP="$(printf '%s' "$SSH_CONNECTION" | awk '{print $1}')"
fi
if [ -z "$CLIENT_IP" ] && [ -n "${SSH_CLIENT:-}" ]; then
    CLIENT_IP="$(printf '%s' "$SSH_CLIENT" | awk '{print $1}')"
fi

echo "SFTP slowness triage on $(hostname)"
date
if [ -n "$CLIENT_IP" ]; then
    info "client address under test: ${CLIENT_IP}"
else
    info "no client address given and none in \$SSH_CONNECTION — sections that need one"
    info "will say so. Pass it as an argument: sudo bash $0 <client-ip>"
fi

# sshd's real port(s). A non-default port is ordinary, and /etc/ssh/sshd_config
# alone misses both an sshd_config.d drop-in and anything sshd was started with,
# so ask the listening sockets and the daemon's own effective config first. Get
# this wrong and section 4 filters for a port nothing is talking on and prints
# an empty table — which reads as "no problem here" when it means "wrong port".
SSHD_BIN="$(command -v sshd 2>/dev/null || echo /usr/sbin/sshd)"
SSHD_PORTS="$(ss -ltnp 2>/dev/null | awk '/"sshd"/ {n=split($4,a,":"); print a[n]}' | sort -un | tr '\n' ' ')"
if [ -z "${SSHD_PORTS// /}" ] && [ -x "$SSHD_BIN" ]; then
    SSHD_PORTS="$("$SSHD_BIN" -T 2>/dev/null | awk '/^port /{print $2}' | sort -un | tr '\n' ' ')"
fi
if [ -z "${SSHD_PORTS// /}" ]; then
    SSHD_PORTS="$(awk '/^[[:space:]]*Port[[:space:]]+[0-9]+/ {print $2}' \
                  /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null | sort -un | tr '\n' ' ')"
fi
SSHD_PORTS="${SSHD_PORTS:-22}"
SSHD_PORT="$(printf '%s' "$SSHD_PORTS" | awk '{print $1}')"
info "sshd port(s): ${SSHD_PORTS% }"

DEF_IFACE="$(ip -4 route show default 2>/dev/null | awk '{print $5; exit}')"
if [ -n "${DEF_IFACE:-}" ]; then
    info "egress interface: ${DEF_IFACE} (MTU $(cat "/sys/class/net/${DEF_IFACE}/mtu" 2>/dev/null || echo '?'))"
else
    info "egress interface: none (no default route — section 4's MTU checks will be blank)"
fi

# Where this app keeps its state. Run under sudo, $HOME is root's, so look in both.
DATA_DIRS=""
for d in /root/.local/share/NetworkSentinel /home/*/.local/share/NetworkSentinel; do
    [ -d "$d" ] && DATA_DIRS="${DATA_DIRS} ${d}"
done

# ---------------------------------------------------------------------------
# 1. This app's own effect on the transfer
# ---------------------------------------------------------------------------
say "1. Is Network Sentinel blocking — or about to block — this client"

echo "  a transfer is only ever slowed by a rule that drops SOME of it; a rule that"
echo "  drops the address stops it dead. Both are worth ruling out first."
echo ""

if [ -n "$CLIENT_IP" ]; then
    echo "  firewall rules naming ${CLIENT_IP}:"
    HITS=""
    have nft && HITS="$(addlines "$HITS" "$(nft list ruleset 2>/dev/null | grep -F -- "$CLIENT_IP")")"
    have iptables && HITS="$(addlines "$HITS" "$(iptables -S 2>/dev/null | grep -F -- "$CLIENT_IP")")"
    if block "$HITS" "(none — this address is not blocked here)"; then FOUND=1; else FOUND=0; fi
    verdict "rules naming the client: ${FOUND} (0 = the slowness is not a block on this node)"
else
    info "(no client address, so no rule lookup)"
fi

echo ""
echo "  rules this app wrote (auto-block writes these):"
OWN=""
have nft && OWN="$(addlines "$OWN" "$(nft list ruleset 2>/dev/null | grep -i 'networksentinel' | head -20)")"
have iptables && OWN="$(addlines "$OWN" "$(iptables -S 2>/dev/null | grep -i 'networksentinel' | head -20)")"
block "$OWN" "(none — this app has written no rules)"

echo ""
echo "  auto-block and exfiltration settings (named keys only):"
SETTINGS_SEEN=0
for d in $DATA_DIRS; do
    f="${d}/settings.json"
    [ -f "$f" ] || continue
    SETTINGS_SEEN=1
    echo "    ${f}:"
    grep -oE '"(AutoBlockEnabled|AutoBlockMinLevel|AutoBlockInbound|AutoBlockOutbound|PreventionDryRun|ExfilMonitorEnabled|ExfilMbPer10Min|SuricataEnabled|ProbeLogEnabled)"[[:space:]]*:[[:space:]]*("[^"]*"|[A-Za-z0-9]+)' \
        "$f" 2>/dev/null | sed 's/^/      /'
done
[ "$SETTINGS_SEEN" = "0" ] && echo "    (no settings.json found — defaults apply: auto-block off, exfil monitor on at 250 MB/10 min)"

echo ""
echo "  large-transfer alerts already recorded (threat-log.jsonl):"
EXFIL_SEEN=0
for d in $DATA_DIRS; do
    f="${d}/threat-log.jsonl"
    [ -f "$f" ] || continue
    if grep -i 'exfiltration' "$f" 2>/dev/null | tail -5 | cut -c1-240 | sed 's/^/    /' | grep -q .; then
        EXFIL_SEEN=1
        grep -i 'exfiltration' "$f" 2>/dev/null | tail -5 | cut -c1-240 | sed 's/^/    /'
    fi
    if [ -n "$CLIENT_IP" ]; then
        grep -F -- "$CLIENT_IP" "$f" 2>/dev/null | tail -5 | cut -c1-240 | sed "s/^/    [client] /"
    fi
done
[ "$EXFIL_SEEN" = "0" ] && echo "    (no exfiltration alert in the log)"

echo ""
if [ -n "$CLIENT_IP" ]; then
    ALLOWED=0
    for d in $DATA_DIRS; do
        for f in "${d}/allowlist.json" "${d}/allowlist-remote-cache.json"; do
            [ -f "$f" ] || continue
            grep -qF -- "$CLIENT_IP" "$f" 2>/dev/null && ALLOWED=1
        done
    done
    if [ "$ALLOWED" = "1" ]; then
        verdict "${CLIENT_IP} IS allowlisted — the exfiltration monitor and auto-block will leave it alone."
    else
        verdict "${CLIENT_IP} is NOT allowlisted. Downloading 250 MB from this box inside 10"
        verdict "minutes therefore raises a High 'Large outbound transfer' threat against it,"
        verdict "and High is the default auto-block level. Allowlist the address you transfer"
        verdict "to (TUI 'n', or the web console's Allowlist tab) — an unblock only suppresses"
        verdict "re-blocking for 24 h, so the transfer would die again tomorrow."
    fi
fi

# ---------------------------------------------------------------------------
# 2. What every packet has to walk through
# ---------------------------------------------------------------------------
say "2. Per-packet cost: how long the firewall chains are"

echo "  chains are evaluated top to bottom, per packet. An interactive shell sends"
echo "  tens of packets a second and never notices; a transfer sends tens of"
echo "  thousands, and pays the whole chain for each one."
echo ""

if have nft; then
    # '# handle N' marks rules AND the table/chain/set that carry them; only rules
    # cost anything per packet, so the containers are subtracted out.
    NS_RULES="$(nft -a list table inet networksentinel 2>/dev/null \
                | grep '# handle [0-9]' | grep -cvE '^[[:space:]]*(table|chain|set|map) ')"
    ALL_RULES="$(nft -a list ruleset 2>/dev/null \
                 | grep '# handle [0-9]' | grep -cvE '^[[:space:]]*(table|chain|set|map) ')"
    info "rules in this app's table (inet networksentinel): ${NS_RULES:-0}"
    info "rules in the whole nftables ruleset:              ${ALL_RULES:-0}"
    SET_ELEMS="$(nft list ruleset 2>/dev/null | grep -c 'elements = ')"
    info "nftables sets in use (a set is one hash lookup, not N comparisons): ${SET_ELEMS:-0}"
else
    info "(nft not installed)"
fi
if have iptables; then
    IPT_RULES="$(iptables -S 2>/dev/null | grep -c '^-A')"
    info "iptables rules: ${IPT_RULES:-0}"
fi

TOTAL_RULES=$(( ${ALL_RULES:-0} + ${IPT_RULES:-0} ))
if [ "$TOTAL_RULES" -gt 2000 ]; then
    verdict "${TOTAL_RULES} rules is enough to cost real throughput on a shared-CPU VPS."
    verdict "This app writes one rule per blocked address, at the head of the chain, so a"
    verdict "long-running node with auto-block on accumulates them. Collapse the pure"
    verdict "address blocks into an nftables set, or expire them (Settings -> auto-block expiry)."
elif [ "$TOTAL_RULES" -gt 500 ]; then
    verdict "${TOTAL_RULES} rules is measurable but rarely the whole story — keep reading."
else
    verdict "${TOTAL_RULES} rules is too few to explain a slow transfer. Not this."
fi

echo ""
echo "  packets handed to userspace for inspection (NFQUEUE — Suricata's IPS mode):"
QUEUE_RULES=""
have nft && QUEUE_RULES="$(addlines "$QUEUE_RULES" "$(nft list ruleset 2>/dev/null | grep -iE '\bqueue\b')")"
have iptables && QUEUE_RULES="$(addlines "$QUEUE_RULES" "$(iptables -S 2>/dev/null | grep -i 'NFQUEUE')")"
if block "$QUEUE_RULES" "(none — nothing is being inspected inline)"; then
    verdict "Traffic is being queued to userspace. EVERY packet then makes a kernel->user"
    verdict "round trip and is inspected before it is released — the single biggest"
    verdict "throughput cost on this list, and one an interactive shell barely feels."
    verdict "Suricata's own drop counters say whether it is also losing packets:"
    verdict "  grep -E 'kernel_drops|drop' /var/log/suricata/stats.log | tail"
fi

# ---------------------------------------------------------------------------
# 3. Is the box simply out of CPU
# ---------------------------------------------------------------------------
say "3. CPU — the other way a fast link delivers slow bytes"

CORES="$(nproc 2>/dev/null || echo '?')"
info "cores: ${CORES}   load: $(cut -d' ' -f1-3 /proc/loadavg 2>/dev/null)"
if [ "$CORES" = "1" ]; then
    verdict "ONE core. Everything that touches a packet — sshd's cipher, WireGuard's,"
    verdict "the firewall chain, the resolver, this app — competes for the same core,"
    verdict "and a bulk transfer is the only workload here big enough to notice."
fi
if grep -qm1 ' aes ' /proc/cpuinfo 2>/dev/null || grep -qm1 'aes' /proc/cpuinfo 2>/dev/null; then
    info "AES-NI: present (so aes128-gcm/aes256-gcm ciphers run at line rate)"
else
    verdict "AES-NI: ABSENT. SSH encryption is then CPU-bound at roughly 30-60 MB/s, and"
    verdict "chacha20-poly1305 will beat the AES ciphers on this box."
fi
echo ""
echo "  top CPU consumers right now:"
ps -eo pcpu,pmem,comm --sort=-pcpu 2>/dev/null | head -8 | sed 's/^/    /'
echo ""
for p in suricata networksentinel sshd; do
    pids="$(pgrep -d, -x "$p" 2>/dev/null)"
    [ -n "$pids" ] && info "${p}: running (pid ${pids})"
done
verdict "A transfer that pins one core is CPU-bound, not network-bound. sshd showing"
verdict "~100% of a core during the transfer is the cipher; suricata showing it is"
verdict "inspection; steal time (below) is the neighbours."
if have vmstat; then
    echo ""
    echo "  cpu breakdown (last column 'st' is steal — CPU the hypervisor gave away):"
    vmstat 1 3 2>/dev/null | tail -n +2 | sed 's/^/    /'
fi

# ---------------------------------------------------------------------------
# 4. The path: loss, MTU, and what the live socket says
# ---------------------------------------------------------------------------
say "4. The path — loss and MTU, which only bulk transfer notices"

CC="$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo '?')"
MTU_PROBE="$(sysctl -n net.ipv4.tcp_mtu_probing 2>/dev/null || echo '?')"
info "congestion control: ${CC}"
info "tcp_mtu_probing:    ${MTU_PROBE}  (0 = off; 1 or 2 recovers from an MTU black hole)"
info "core rmem_max/wmem_max: $(sysctl -n net.core.rmem_max 2>/dev/null) / $(sysctl -n net.core.wmem_max 2>/dev/null)"
info "tcp_rmem (min default max): $(sysctl -n net.ipv4.tcp_rmem 2>/dev/null | tr '\t' ' ')"
info "tcp_wmem (min default max): $(sysctl -n net.ipv4.tcp_wmem 2>/dev/null | tr '\t' ' ')"
verdict "The THIRD tcp_rmem/tcp_wmem number is the ceiling autotuning may reach, and it"
verdict "is what a transfer runs into. net.core.*mem_max only caps a program that sets"
verdict "its buffer explicitly, so a 212992 there is not by itself a limit on ssh."
verdict "A window has to hold rtt x bandwidth: 100 ms at 100 Mbit needs ~1.25 MB."

echo ""
echo "  live SSH sockets on port(s) ${SSHD_PORTS% } — run this DURING the slow transfer,"
echo "  the numbers here are the answer:"
if have ss; then
    SS_FILTER=""
    for p in $SSHD_PORTS; do
        [ -n "$SS_FILTER" ] && SS_FILTER="${SS_FILTER} or "
        SS_FILTER="${SS_FILTER}sport = :${p} or dport = :${p}"
    done
    SS_OUT="$(ss -tinp state established "( ${SS_FILTER} )" 2>/dev/null | head -30)"
    block "$SS_OUT" "(no established SSH session on those ports — either nothing is connected, or sshd is on a port this did not find. Re-run during the slow transfer.)"
else
    info "(ss not installed — iproute2 provides it)"
fi
echo ""
verdict "In that output: 'retrans:' climbing during a transfer is packet loss, and loss"
verdict "is what separates a fast shell from a slow transfer — one lost packet in a few"
verdict "hundred halves a bulk stream's window and is imperceptible interactively."
verdict "'rtt:' is the round trip; 'cwnd:' times MSS divided by rtt is the ceiling this"
verdict "connection can reach no matter what the link is worth."
verdict "'mss:' well under 1448 on a 1500-MTU path means something is clamping it."

echo ""
echo "  is the transfer going through a tunnel:"
WG_IFACES="$(ip -brief link show type wireguard 2>/dev/null | awk '{print $1}')"
if [ -n "$WG_IFACES" ]; then
    for w in $WG_IFACES; do
        info "${w}: MTU $(cat "/sys/class/net/${w}/mtu" 2>/dev/null || echo '?'), $(wg show "$w" peers 2>/dev/null | wc -l) peer(s)"
    done
    if [ -n "$CLIENT_IP" ]; then
        VIA="$(ip route get "$CLIENT_IP" 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}' | head -1)"
        info "route to ${CLIENT_IP} leaves via: ${VIA:-unknown}"
        for w in $WG_IFACES; do
            [ "$VIA" = "$w" ] && verdict "THE TRANSFER GOES THROUGH THE TUNNEL. Every byte is encrypted twice — once"
            [ "$VIA" = "$w" ] && verdict "by SSH, once by WireGuard — and WireGuard's per-peer crypto is effectively"
            [ "$VIA" = "$w" ] && verdict "one CPU's worth. On the single core section 3 counted, that is a hard"
            [ "$VIA" = "$w" ] && verdict "throughput ceiling an interactive shell never approaches. Compare a transfer"
            [ "$VIA" = "$w" ] && verdict "to this host's PUBLIC address with the tunnel down: if that is fast, the"
            [ "$VIA" = "$w" ] && verdict "tunnel is the cost, not SFTP."
        done
    else
        verdict "Pass the client address to find out whether its traffic takes the tunnel."
    fi
    verdict "A tunnel MTU above the path's (1420 is the usual safe value over a 1500 link)"
    verdict "shows up as a transfer that starts and stalls while the shell stays fine."
else
    echo "    (no WireGuard interface — the transfer takes the plain route)"
fi

echo ""
echo "  does anything here drop the ICMP that Path MTU Discovery needs:"
ICMP_RULES=""
have nft && ICMP_RULES="$(addlines "$ICMP_RULES" "$(nft list ruleset 2>/dev/null | grep -iE 'icmp.*(drop|reject)')")"
have iptables && ICMP_RULES="$(addlines "$ICMP_RULES" "$(iptables -S 2>/dev/null | grep -iE 'icmp.*(DROP|REJECT)')")"
if block "$ICMP_RULES" "(nothing here drops ICMP)"; then
    verdict "ICMP is being dropped. Blocking 'fragmentation needed' (ICMP type 3 code 4)"
    verdict "creates an MTU black hole: the handshake and an interactive shell use small"
    verdict "packets and work perfectly, then a transfer sends full-size packets that"
    verdict "vanish with no error. Classic 'ssh fine, sftp/scp hangs at 0%'."
fi

# ---------------------------------------------------------------------------
# 5. Traffic shaping — rare, decisive when present
# ---------------------------------------------------------------------------
say "5. Traffic shaping on the egress interface"

if have tc && [ -n "${DEF_IFACE:-}" ]; then
    tc -s qdisc show dev "$DEF_IFACE" 2>/dev/null | head -12 | sed 's/^/    /'
    if tc qdisc show dev "$DEF_IFACE" 2>/dev/null | grep -qiE 'tbf|htb|police|cake|hfsc'; then
        verdict "A shaping qdisc is installed. It caps throughput and leaves latency alone —"
        verdict "which is precisely 'the shell is fine, the transfer is slow'."
    else
        verdict "No rate-limiting qdisc (fq/fq_codel/pfifo_fast are not shapers). Not this."
    fi
else
    info "(tc not installed, or no default interface)"
fi

# ---------------------------------------------------------------------------
# 6. Slow to CONNECT is a different fault
# ---------------------------------------------------------------------------
say "6. Connect-time cost (complaint A: the pause BEFORE anything transfers)"

echo "  sshd settings that add seconds to every new session:"
# sshd -T prints the EFFECTIVE config — drop-ins and command-line flags included —
# which is what the daemon is actually running, unlike any one file.
SSHD_KEYS="$("$SSHD_BIN" -T 2>/dev/null | grep -iE '^(usedns|gssapiauthentication|maxstartups|logingracetime|subsystem)')"
[ -z "$SSHD_KEYS" ] && SSHD_KEYS="$(grep -inE '^[[:space:]]*(UseDNS|GSSAPIAuthentication|MaxStartups|LoginGraceTime)' \
             /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null)"
block "$SSHD_KEYS" "(nothing set — the defaults apply, and both costly ones are off: UseDNS no, GSSAPI no)"

echo ""
echo "  per-user overrides (a Match block can give the sftp account a chroot the"
echo "  shell account does not have):"
MATCHES="$(grep -inE '^[[:space:]]*(Match|ChrootDirectory|ForceCommand)' \
           /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null)"
block "$MATCHES" "(no Match, ChrootDirectory or ForceCommand — every account gets the same treatment)"

if [ -n "$CLIENT_IP" ]; then
    echo ""
    echo "  reverse DNS for the client, timed — sshd waits on this when UseDNS is yes:"
    if have dig; then
        S="$(date +%s%N)"; dig +short +time=3 +tries=1 -x "$CLIENT_IP" >/dev/null 2>&1; E="$(date +%s%N)"
        info "reverse lookup took $(( (E - S) / 1000000 )) ms"
    elif have getent; then
        S="$(date +%s%N)"; getent hosts "$CLIENT_IP" >/dev/null 2>&1; E="$(date +%s%N)"
        info "reverse lookup took $(( (E - S) / 1000000 )) ms"
    fi
    verdict "Over ~1000 ms with UseDNS yes means every connection pays it. SFTP clients that"
    verdict "open a second connection (or one per transfer, as several GUI clients do) pay"
    verdict "it again each time, which is why they feel slow where one shell does not."
fi

echo ""
echo "  the sftp subsystem in use:"
SUBSYS="$(grep -inE '^[[:space:]]*Subsystem' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null)"
block "$SUBSYS" "(no Subsystem line — the compiled-in default sftp-server is used)"
verdict "'internal-sftp' runs inside sshd; 'sftp-server' forks a helper per session."
verdict "Neither is slow by itself, but a ChrootDirectory on a slow or network filesystem is."

# ---------------------------------------------------------------------------
# 7. The half this node cannot see
# ---------------------------------------------------------------------------
say "Run these on the client — they separate the network from SFTP itself"

cat <<EOF
  # 1. What the SSH transport is worth, with SFTP taken out of the picture.
  #    This is the control. It uses the same host, port, key and cipher:
  ssh ${SSHD_PORT:+-p $SSHD_PORT }<user>@<this-host> 'dd if=/dev/zero bs=1M count=500' > /dev/null

  # 2. What SFTP gets over that same transport, with its defaults. The host:path
  #    form does the whole transfer in one shot — no interactive session:
  sftp ${SSHD_PORT:+-P $SSHD_PORT }<user>@<this-host>:/path/to/500mb.bin /tmp/sftp-speedtest.bin

  # 3. The same transfer with the protocol's windows opened up. Defaults are a
  #    32 KB buffer and 64 outstanding requests = 2 MB in flight, which caps you
  #    at 2 MB / RTT no matter how fat the link is: about 20 MB/s at 100 ms,
  #    10 MB/s at 200 ms. These flags raise it 8x:
  sftp -B 262144 -R 256 ${SSHD_PORT:+-P $SSHD_PORT }<user>@<this-host>:/path/to/500mb.bin /tmp/sftp-speedtest.bin
  rm -f /tmp/sftp-speedtest.bin

  # 4. Round-trip time to this host — every number above depends on it:
  ping -c 20 <this-host>

  # 5. If the transfer is MANY SMALL FILES rather than one big one, SFTP pays
  #    several round trips per file and no buffer size helps. Stream it instead:
  ssh <user>@<this-host> 'tar cf - /path/to/dir' | tar xf -
  rsync -az -e ssh <user>@<this-host>:/path/to/dir/ ./dir/

  # 6. MTU black hole, from the client side (1472 + 28 = 1500):
  ping -c 3 -M do -s 1472 <this-host>    # Linux
  ping -c 3 -D -s 1472 <this-host>       # macOS
  #    Fails while a normal ping succeeds -> lower the MTU or turn on tcp_mtu_probing.
EOF

say "Reading the result"
cat <<'EOF'
  Section 1 names a rule        -> the client is blocked, not slowed. If auto-block wrote
                                   it, ALLOWLIST the address rather than unblocking: an
                                   unblock lapses after 24 h and the transfer dies again.
  Section 1 shows an exfil      -> a download from this box tripped the exfiltration
    alert for your own client      monitor (250 MB / 10 min, High, at or above the default
                                   auto-block level). Allowlist the address you transfer to,
                                   or raise Settings -> exfiltration threshold. This is the
                                   one cause on the list that this app creates itself.
  Section 2 shows NFQUEUE       -> Suricata is inspecting every packet inline. Expect a
                                   large throughput cut and an untouched interactive feel.
                                   Bypass the SSH port, or run Suricata in IDS (af-packet)
                                   mode where it copies packets instead of gating them.
  Section 2 shows 1000s of      -> one rule per blocked address, walked per packet. Expire
    rules                          old auto-blocks or collapse them into an nftables set.
  Section 3 pins one core       -> CPU-bound. Without AES-NI use chacha20-poly1305; with
                                   high steal time the VPS neighbours are the ceiling.
  Section 4 shows retrans       -> packet loss on the path. This is the most common cause
                                   of "shell fine, transfer slow" that has nothing to do
                                   with this host. Try BBR (net.ipv4.tcp_congestion_control
                                   = bbr), which tolerates loss far better than cubic.
  Section 4 shows a low mss     -> or the client-side ping test in item 6 fails: an MTU
    or drops ICMP                  black hole. Small packets pass, full ones vanish.
  Section 4 says the transfer   -> WireGuard encrypts every byte a second time, on one
    takes the tunnel               core's worth of crypto. Test against the host's public
                                   address with the tunnel down before blaming SFTP.
  Section 5 shows a shaper      -> a qdisc is capping throughput. Read its rate.
  Section 6 slow reverse DNS    -> only explains a slow CONNECT, never a slow transfer.
    with UseDNS yes                Set UseDNS no.
  Client test 1 FAST,           -> nothing here is wrong. The loss is inside SFTP: raise
    test 2 SLOW                    -B and -R as in item 3, or use rsync/scp/tar over ssh.
                                   A GUI client (FileZilla, Cyberduck) or a file-manager
                                   mount (gvfs, sshfs) is the usual reason: those issue
                                   small serialised reads and pay a round trip for each.
  Both client tests SLOW        -> the SSH transport itself is slow, so it is one of
                                   sections 2-5, not SFTP.
EOF

say "Done"
echo "Nothing above changed any state. Paste the whole output back."
