#!/usr/bin/env bash
# Install AdGuard Home as the filtering resolver for this node's VPN clients.
#
# What this buys you that Network Sentinel cannot: blocking by *name*, before a
# connection exists. Network Sentinel sees a connection once it is established and
# can then block the address; a resolver refuses to answer, so the client never
# learns an address and never dials out. The two do not overlap — a name-based
# blocklist misses malware that hard-codes an IP, which is exactly the case the
# threat-intel feeds catch.
#
# The resulting arrangement is the one the README's DNS-hygiene section asks for:
#
#     host + tunnel clients -> AdGuard Home (this node) -> [DoT] -> upstream
#
# Queries never leave the node in the clear, and because the resolver is local you
# keep full visibility while the network sees nothing.
#
# Usage:
#   sudo ./scripts/setup-dns-filter.sh                 # interactive, detects the tunnel
#   sudo ./scripts/setup-dns-filter.sh --dry-run       # print every change, make none
#   sudo ./scripts/setup-dns-filter.sh --uninstall     # reverse everything, restore backups
#
# Options:
#   --tunnel-iface IFACE   Tunnel interface (default: autodetected wg*/xfrm/ipsec)
#   --upstream NAME        quad9 (default) | cloudflare | adguard | nextdns:<id>
#   --stray-dns MODE       redirect (default) | reject | allow — what happens to a client
#                          that ignores the pushed resolver and dials 8.8.8.8 directly
#   --ui-port PORT         AdGuard web UI port, tunnel-bound only (default: 3000)
#   --version TAG          Pin an AdGuard Home release (default: latest)
#   --no-firewall          Skip all firewall rules
#   --no-host-resolv       Leave this node's own resolver configuration alone
#   --assume-yes           No prompts
#
# Everything it touches is backed up under /var/backups/ns-dns-filter/<timestamp>/
# and --uninstall puts it all back.
set -euo pipefail

# ---------------------------------------------------------------------------
# Defaults and argument parsing
# ---------------------------------------------------------------------------
TUNNEL_IFACE=""
UPSTREAM_NAME="quad9"
STRAY_DNS="redirect"
UI_PORT="3000"
AGH_VERSION="latest"
DO_FIREWALL=1
DO_HOST_RESOLV=1
ASSUME_YES=0
DRY_RUN=0
UNINSTALL=0

AGH_DIR="/opt/AdGuardHome"
AGH_BIN="${AGH_DIR}/AdGuardHome"
AGH_CONF="${AGH_DIR}/AdGuardHome.yaml"
UNIT="/etc/systemd/system/AdGuardHome.service"
STATE_DIR="/var/lib/ns-dns-filter"
BACKUP_ROOT="/var/backups/ns-dns-filter"

# Our own nftables tables. Deliberately NOT "networksentinel": FirewallService owns
# that table and its "Remove all rules" deletes every rule whose comment starts with
# "NetworkSentinel". Sharing either would let the app wipe the rules that keep this
# resolver from being an open relay.
NFT_TABLE="dnsfilter"
NFT_NAT_TABLE="dnsfilter_nat"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --tunnel-iface) TUNNEL_IFACE="${2:?}"; shift 2 ;;
    --upstream)     UPSTREAM_NAME="${2:?}"; shift 2 ;;
    --stray-dns)    STRAY_DNS="${2:?}"; shift 2 ;;
    --ui-port)      UI_PORT="${2:?}"; shift 2 ;;
    --version)      AGH_VERSION="${2:?}"; shift 2 ;;
    --no-firewall)  DO_FIREWALL=0; shift ;;
    --no-host-resolv) DO_HOST_RESOLV=0; shift ;;
    --assume-yes|-y) ASSUME_YES=1; shift ;;
    --dry-run)      DRY_RUN=1; shift ;;
    --uninstall)    UNINSTALL=1; shift ;;
    -h|--help)      sed -n '2,40p' "$0"; exit 0 ;;
    *) printf 'Unknown option: %s (try --help)\n' "$1" >&2; exit 1 ;;
  esac
done

[[ -t 0 ]] || ASSUME_YES=1

say()  { printf '%s\n' "$*"; }
info() { printf '  %s\n' "$*"; }
warn() { printf 'Warning: %s\n' "$*" >&2; }
die()  { printf 'Error: %s\n' "$*" >&2; exit 1; }
step() { printf '\n== %s\n' "$*"; }

# Every mutation goes through run(), so --dry-run is honest by construction rather
# than by remembering to check a flag at each call site.
run() {
  if [[ "$DRY_RUN" == "1" ]]; then
    printf '  [dry-run] %s\n' "$*"
    return 0
  fi
  "$@"
}

confirm() {
  [[ "$ASSUME_YES" == "1" ]] && return 0
  local answer
  read -r -p "$1 [y/N] " answer
  [[ "$answer" =~ ^[Yy] ]]
}

[[ "$(id -u)" == "0" ]] || die "run this with sudo — it installs a service and writes firewall rules"

case "$STRAY_DNS" in
  redirect|reject|allow) ;;
  *) die "--stray-dns must be redirect, reject or allow" ;;
esac

# ---------------------------------------------------------------------------
# Backups
# ---------------------------------------------------------------------------
STAMP="$(date +%Y%m%d-%H%M%S)"
BACKUP_DIR="${BACKUP_ROOT}/${STAMP}"

backup_file() {
  local path="$1"
  [[ -e "$path" ]] || return 0
  run mkdir -p "${BACKUP_DIR}$(dirname "$path")"
  run cp -a "$path" "${BACKUP_DIR}${path}"
  info "backed up ${path}"
}

# ---------------------------------------------------------------------------
# Uninstall
# ---------------------------------------------------------------------------
if [[ "$UNINSTALL" == "1" ]]; then
  step "Removing the DNS filter"

  if [[ -f "${STATE_DIR}/backup-dir" ]]; then
    RESTORE_FROM="$(cat "${STATE_DIR}/backup-dir")"
  else
    RESTORE_FROM=""
  fi

  systemctl is-active --quiet AdGuardHome 2>/dev/null && run systemctl stop AdGuardHome
  systemctl is-enabled --quiet AdGuardHome 2>/dev/null && run systemctl disable AdGuardHome
  [[ -f "$UNIT" ]] && { run rm -f "$UNIT"; run systemctl daemon-reload; }

  if command -v nft >/dev/null 2>&1; then
    run nft delete table "inet ${NFT_TABLE}" 2>/dev/null || true
    run nft delete table "ip ${NFT_NAT_TABLE}" 2>/dev/null || true
  fi
  if [[ -f "${STATE_DIR}/iptables-rules" ]]; then
    # Each recorded line is the -A form; replay it as -D to undo exactly what we added.
    while IFS= read -r rule; do
      [[ -n "$rule" ]] || continue
      # shellcheck disable=SC2086
      run iptables ${rule/-A/-D} 2>/dev/null || true
    done < "${STATE_DIR}/iptables-rules"
  fi

  if [[ -n "$RESTORE_FROM" && -d "$RESTORE_FROM" ]]; then
    for f in /etc/systemd/resolved.conf /etc/resolv.conf; do
      if [[ -e "${RESTORE_FROM}${f}" ]]; then
        run cp -a "${RESTORE_FROM}${f}" "$f"
        info "restored ${f}"
      fi
    done
    if systemctl is-active --quiet systemd-resolved 2>/dev/null; then
      run systemctl restart systemd-resolved || true
    fi
  else
    warn "no backup record found — check ${BACKUP_ROOT} and restore /etc/resolv.conf by hand if name resolution is broken"
  fi

  say ""
  say "AdGuard Home service and rules removed. The binary and its config are left in"
  say "${AGH_DIR} in case you want the query log; delete it with:  rm -rf ${AGH_DIR}"
  say "Remember to drop the 'DNS =' line from your client configs."
  exit 0
fi

# ---------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------
step "Checking the node"

command -v systemctl >/dev/null 2>&1 || die "this script manages a systemd service; systemd not found"
for tool in curl tar sha256sum ip ss; do
  command -v "$tool" >/dev/null 2>&1 || die "missing required tool: ${tool}"
done
command -v python3 >/dev/null 2>&1 \
  || warn "python3 not found - the client subnet will be guessed as a /24 and settings.json will not be updated"

case "$(uname -m)" in
  x86_64|amd64)  AGH_ARCH="linux_amd64" ;;
  aarch64|arm64) AGH_ARCH="linux_arm64" ;;
  armv7l|armv6l) AGH_ARCH="linux_armv7" ;;
  i386|i686)     AGH_ARCH="linux_386" ;;
  *) die "unsupported architecture: $(uname -m)" ;;
esac
info "architecture: ${AGH_ARCH}"

# --- Find the tunnel -------------------------------------------------------
# WireGuard interfaces are identifiable from sysfs without root or a subprocess,
# the same way WireGuardMonitor finds them. IPsec shows up as xfrm/ipsec links.
detect_tunnel() {
  local iface
  for iface in /sys/class/net/*; do
    [[ -e "${iface}/uevent" ]] || continue
    if grep -q '^DEVTYPE=wireguard$' "${iface}/uevent" 2>/dev/null; then
      basename "$iface"; return 0
    fi
  done
  for iface in /sys/class/net/*; do
    local name; name="$(basename "$iface")"
    case "$name" in
      ipsec*|xfrm*|tun*|ppp*) printf '%s\n' "$name"; return 0 ;;
    esac
  done
  return 1
}

if [[ -z "$TUNNEL_IFACE" ]]; then
  TUNNEL_IFACE="$(detect_tunnel || true)"
  [[ -n "$TUNNEL_IFACE" ]] || die "no tunnel interface found — bring the VPN up first, or pass --tunnel-iface"
fi
[[ -e "/sys/class/net/${TUNNEL_IFACE}" ]] || die "interface ${TUNNEL_IFACE} does not exist"

# The address the clients will point at, and the subnet they live in.
TUNNEL_CIDR="$(ip -4 -o addr show dev "$TUNNEL_IFACE" | awk '{print $4; exit}')"
[[ -n "$TUNNEL_CIDR" ]] || die "${TUNNEL_IFACE} has no IPv4 address — bring the tunnel up first"
TUNNEL_IP="${TUNNEL_CIDR%%/*}"
TUNNEL_PREFIX="${TUNNEL_CIDR##*/}"

# Network address of the client subnet, so the firewall admits the tunnel and
# nothing else. Derived rather than assumed: a /24 guess would be wrong on the
# common 10.x.x.1/32-plus-AllowedIPs layouts.
TUNNEL_SUBNET="$(python3 -c '
import ipaddress, sys
ip, prefix = sys.argv[1], int(sys.argv[2])
# A /32 on the server side means the subnet lives in AllowedIPs; fall back to the
# enclosing /24, which is what wg-quick own examples produce.
if prefix >= 31:
    prefix = 24
print(ipaddress.ip_network(f"{ip}/{prefix}", strict=False))
' "$TUNNEL_IP" "$TUNNEL_PREFIX" 2>/dev/null || true)"
# Fallback for a host without python3: the enclosing /24, as a network address.
[[ -n "$TUNNEL_SUBNET" ]] || TUNNEL_SUBNET="${TUNNEL_IP%.*}.0/24"

info "tunnel interface: ${TUNNEL_IFACE}"
info "resolver address: ${TUNNEL_IP}  (this is what clients will use)"

# Anything already holding port 53 on the tunnel address — or on the wildcard, which
# covers it — stops AdGuard Home dead. The failure is unpleasant to find later: the
# UDP sockets bind, only the TCP one collides, so the daemon exits 1 and systemd
# restarts it forever. Nothing is listening on the admin port either, so the switch
# in the app can only report that the resolver could not be reached, which says
# nothing about a port conflict. Catch it here, while nothing has been installed.
if command -v ss >/dev/null 2>&1; then
  DNS_HOLDERS="$(ss -lntupH 2>/dev/null | awk -v ip="$TUNNEL_IP" '
    {
      local = $5
      if (local !~ /:53$/) next
      host = local
      sub(/:53$/, "", host)
      if (host == ip || host == "0.0.0.0" || host == "*" || host == "[::]" || host == "::") {
        proc = ""
        for (i = 7; i <= NF; i++) proc = proc (proc == "" ? "" : " ") $i
        printf "  %-5s %-24s %s\n", $1, local, proc
      }
    }')"
  if [[ -n "$DNS_HOLDERS" ]]; then
    say ""
    say "Already listening on port 53 where AdGuard Home needs to be:"
    say "$DNS_HOLDERS"
    say ""
    die "port 53 is taken on ${TUNNEL_IP} — stop that resolver (or bind it elsewhere) and re-run; nothing has been changed"
  fi
fi
info "client subnet:    ${TUNNEL_SUBNET}"

if [[ "$TUNNEL_IP" == 0.0.0.0 || "$TUNNEL_IP" == 127.* ]]; then
  die "refusing to bind the resolver to ${TUNNEL_IP}"
fi

# --- Upstream --------------------------------------------------------------
# DoT rather than DoH: port 853 is identifiable, so the DNS-hygiene monitor can
# recognise it as encrypted DNS without being told. A DoH upstream on 443 would be
# indistinguishable from web traffic and would have to be allowlisted by hand.
case "$UPSTREAM_NAME" in
  quad9)      UPSTREAM_URL="tls://dns.quad9.net";        BOOTSTRAP='9.9.9.9, 149.112.112.112' ;;
  cloudflare) UPSTREAM_URL="tls://security.cloudflare-dns.com"; BOOTSTRAP='1.1.1.2, 1.0.0.2' ;;
  adguard)    UPSTREAM_URL="tls://dns.adguard-dns.com";  BOOTSTRAP='94.140.14.14, 94.140.15.15' ;;
  nextdns:*)  UPSTREAM_URL="tls://${UPSTREAM_NAME#nextdns:}.dns.nextdns.io"; BOOTSTRAP='45.90.28.0, 45.90.30.0' ;;
  *) die "unknown --upstream: ${UPSTREAM_NAME}" ;;
esac
info "upstream: ${UPSTREAM_URL} (encrypted, port 853)"

# --- Port 53 ---------------------------------------------------------------
# We bind 127.0.0.1:53 and the tunnel address. systemd-resolved's stub sits on
# 127.0.0.53:53, so there is normally no conflict — but a resolver configured to
# listen more broadly would collide, and finding that out after the service fails
# to start is a worse time.
if ss -lnupt 2>/dev/null | awk '{print $5}' | grep -qE "(^|[^0-9.])(0\.0\.0\.0|${TUNNEL_IP//./\\.}|127\.0\.0\.1):53$"; then
  warn "something is already listening on port 53 at 0.0.0.0, 127.0.0.1 or ${TUNNEL_IP}:"
  ss -lnupt 2>/dev/null | grep ':53 ' || true
  confirm "Continue anyway?" || die "aborted — free port 53 first"
fi

say ""
say "Plan:"
say "  1. install AdGuard Home to ${AGH_DIR}, bound to ${TUNNEL_IP}:53 and 127.0.0.1:53"
say "  2. filter with the AdGuard base + malware/phishing blocklists"
say "  3. forward upstream over DoT to ${UPSTREAM_URL}"
say "  4. firewall: accept 53 only from ${TUNNEL_SUBNET}; never from the internet"
say "  5. stray client DNS (hardcoded 8.8.8.8 etc): ${STRAY_DNS}"
[[ "$DO_HOST_RESOLV" == "1" ]] && say "  6. point this node's own resolver at it"
say ""
confirm "Proceed?" || die "aborted"

run mkdir -p "$STATE_DIR" "$BACKUP_DIR"
[[ "$DRY_RUN" == "1" ]] || printf '%s\n' "$BACKUP_DIR" > "${STATE_DIR}/backup-dir"

# ---------------------------------------------------------------------------
# Install AdGuard Home
# ---------------------------------------------------------------------------
step "Installing AdGuard Home"

if [[ -x "$AGH_BIN" ]]; then
  info "already installed at ${AGH_BIN} — reusing the binary"
else
  if [[ "$AGH_VERSION" == "latest" ]]; then
    # Read the body first: piping curl into `grep -m1` makes grep exit on the first
    # match and close the pipe, so curl dies of EPIPE and prints "curl: (23) Failure
    # writing output to destination" — an alarming line for a step that in fact
    # succeeded, printed right where a real download error would appear.
    AGH_RELEASE_JSON="$(curl -fsSL https://api.github.com/repos/AdguardTeam/AdGuardHome/releases/latest || true)"
    AGH_VERSION="$(grep -m1 '"tag_name"' <<<"$AGH_RELEASE_JSON" | cut -d'"' -f4 || true)"
    [[ -n "$AGH_VERSION" ]] || die "could not determine the latest AdGuard Home release — pass --version"
  fi
  info "version: ${AGH_VERSION}"

  TARBALL="AdGuardHome_${AGH_ARCH}.tar.gz"
  BASE="https://github.com/AdguardTeam/AdGuardHome/releases/download/${AGH_VERSION}"
  TMP="$(mktemp -d)"
  trap 'rm -rf "$TMP"' EXIT

  info "downloading ${TARBALL}"
  run curl -fsSL -o "${TMP}/${TARBALL}" "${BASE}/${TARBALL}"
  run curl -fsSL -o "${TMP}/checksums.txt" "${BASE}/checksums.txt"

  # Verify before unpacking. A resolver is the single most valuable thing on this
  # box to tamper with — it decides where every client goes.
  if [[ "$DRY_RUN" != "1" ]]; then
    # The release file lists names as "./AdGuardHome_linux_amd64.tar.gz", so a pattern
    # anchored on a leading space selects no line at all; sha256sum then read an empty
    # list, said so, and this script reported it as a checksum *mismatch* — the one
    # verdict that means the download was tampered with. Compare the basename instead
    # of pattern-matching the line, and keep the two failures apart: no line for this
    # file is a packaging change, a differing hash is a reason to stop.
    expected="$(awk -v want="$TARBALL" '
      { name = $NF
        sub(/^\.\//, "", name)
        sub(/^\*/, "", name)
        if (name == want) { print $1; exit } }' "${TMP}/checksums.txt")"
    [[ -n "$expected" ]] \
      || die "checksums.txt has no line for ${TARBALL} — refusing to install"
    actual="$(sha256sum "${TMP}/${TARBALL}" | cut -d' ' -f1)"
    [[ "$expected" == "$actual" ]] \
      || die "checksum mismatch on ${TARBALL}: expected ${expected}, got ${actual} — refusing to install"
    info "sha256 verified"
  fi

  run tar -xzf "${TMP}/${TARBALL}" -C "$TMP"
  run mkdir -p "$AGH_DIR"
  run cp "${TMP}/AdGuardHome/AdGuardHome" "$AGH_BIN"
  run chmod 0755 "$AGH_BIN"
fi

# Binding port 53 needs the capability; running as root for a network-facing daemon
# is avoidable, so give the binary CAP_NET_BIND_SERVICE and run it unprivileged.
if command -v setcap >/dev/null 2>&1; then
  run setcap 'cap_net_bind_service=+eip' "$AGH_BIN" || warn "setcap failed; the unit will fall back to root"
  AGH_USER="adguardhome"
  if ! id "$AGH_USER" >/dev/null 2>&1; then
    run useradd --system --no-create-home --shell /usr/sbin/nologin "$AGH_USER"
    info "created system user ${AGH_USER}"
  fi
else
  warn "setcap not available — AdGuard Home will run as root"
  AGH_USER="root"
fi

# ---------------------------------------------------------------------------
# Admin password for the web UI
# ---------------------------------------------------------------------------
step "Web UI credentials"

AGH_HASH=""
AGH_API_PASS=""
if [[ "$DRY_RUN" != "1" ]]; then
  if [[ "$ASSUME_YES" == "1" ]]; then
    warn "non-interactive: leaving the setup wizard enabled (reachable on ${TUNNEL_IP}:${UI_PORT} only)"
  else
    read -r -s -p "  Password for the AdGuard admin UI (blank = use the setup wizard): " AGH_PASS; echo
    if [[ -n "$AGH_PASS" ]]; then
      if command -v htpasswd >/dev/null 2>&1; then
        AGH_HASH="$(htpasswd -B -n -b admin "$AGH_PASS" | cut -d: -f2)"
      elif python3 -c 'import bcrypt' 2>/dev/null; then
        AGH_HASH="$(python3 -c 'import bcrypt,sys; print(bcrypt.hashpw(sys.argv[1].encode(), bcrypt.gensalt()).decode())' "$AGH_PASS")"
      else
        warn "no bcrypt tool (install apache2-utils) — falling back to the setup wizard"
      fi
      # AdGuard stores the bcrypt hash; Network Sentinel's switch has to authenticate
      # to the same API, so it needs the password itself. It goes into settings.json,
      # which is written owner-only and already holds the TLS key password.
      [[ -n "$AGH_HASH" ]] && AGH_API_PASS="$AGH_PASS"
      unset AGH_PASS
    fi
  fi
fi

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
step "Writing ${AGH_CONF}"

backup_file "$AGH_CONF"

if [[ -n "$AGH_HASH" ]]; then
  USERS_BLOCK="users:
  - name: admin
    password: ${AGH_HASH}"
else
  USERS_BLOCK="users: []"
fi

# bind_hosts is the whole security story for this file. AdGuard Home defaults to
# 0.0.0.0, which on a public VPS is an open resolver: free DNS amplification for
# anyone who finds it, and your address in the abuse reports. It binds the tunnel
# address and loopback, and nothing else.
if [[ "$DRY_RUN" == "1" ]]; then
  info "[dry-run] would write config binding ${TUNNEL_IP} and 127.0.0.1"
else
  cat > "$AGH_CONF" <<YAML
# Written by scripts/setup-dns-filter.sh — safe to edit; AdGuard Home rewrites it
# when you change settings in the UI.
http:
  address: ${TUNNEL_IP}:${UI_PORT}
  session_ttl: 720h
${USERS_BLOCK}
auth_attempts: 5
block_auth_min: 15
theme: auto
dns:
  bind_hosts:
    - ${TUNNEL_IP}
    - 127.0.0.1
  port: 53
  # Answer only for the tunnel and this host. Everything else is refused outright,
  # which is the difference between a resolver and an amplification relay.
  allowed_clients:
    - ${TUNNEL_SUBNET}
    - 127.0.0.1
  ratelimit: 40
  refuse_any: true
  upstream_dns:
    - ${UPSTREAM_URL}
  bootstrap_dns: [${BOOTSTRAP}]
  upstream_mode: load_balance
  enable_dnssec: true
  cache_size: 8388608
  cache_ttl_min: 60
  cache_optimistic: true
  # Do not fall back to plaintext when the encrypted upstream fails. Silent fallback
  # is precisely the failure the DNS-hygiene monitor exists to catch; better a loud
  # outage than queries quietly leaving in the clear.
  fallback_dns: []
filtering:
  protection_enabled: true
  filtering_enabled: true
  safebrowsing_enabled: true
  parental_enabled: false
  safe_search:
    enabled: false
  blocking_mode: nxdomain
  filters_update_interval: 12
filters:
  - enabled: true
    url: https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt
    name: AdGuard DNS filter
    id: 1
  - enabled: true
    url: https://adguardteam.github.io/HostlistsRegistry/assets/filter_9.txt
    name: The Big List of Hacked Malware Web Sites
    id: 9
  - enabled: true
    url: https://adguardteam.github.io/HostlistsRegistry/assets/filter_12.txt
    name: Dandelion Sprout's Anti-Malware List
    id: 12
  # The two lists that actually answer "stop me opening a bad site". Phishing is
  # the case a plain ad blocker misses: the domain is days old and hosts nothing
  # but a login form that looks like your bank.
  - enabled: true
    url: https://adguardteam.github.io/HostlistsRegistry/assets/filter_18.txt
    name: Phishing Army
    id: 18
  - enabled: true
    url: https://adguardteam.github.io/HostlistsRegistry/assets/filter_30.txt
    name: Phishing URL Blocklist (PhishTank and OpenPhish)
    id: 30
  - enabled: true
    url: https://adguardteam.github.io/HostlistsRegistry/assets/filter_8.txt
    name: NoCoin Filter List
    id: 8
  # Domains used to bootstrap browser DNS-over-HTTPS. Blocking them pushes Chrome
  # and Firefox back onto this resolver instead of silently routing around it.
  - enabled: true
    url: https://raw.githubusercontent.com/dibdot/DoH-IP-blocklists/master/doh-domains_overall.txt
    name: DoH bypass domains
    id: 1001
whitelist_filters: []
user_rules: []
querylog:
  enabled: true
  interval: 24h
  anonymize_client_ip: false
statistics:
  enabled: true
  interval: 168h
log:
  verbose: false
schema_version: 29
YAML
  run chmod 0640 "$AGH_CONF"
  [[ "$AGH_USER" != "root" ]] && run chown -R "${AGH_USER}:${AGH_USER}" "$AGH_DIR"
fi

# ---------------------------------------------------------------------------
# systemd unit
# ---------------------------------------------------------------------------
step "Installing the service"

backup_file "$UNIT"
if [[ "$DRY_RUN" == "1" ]]; then
  info "[dry-run] would write ${UNIT}"
else
  cat > "$UNIT" <<UNIT_EOF
[Unit]
Description=AdGuard Home — filtering DNS resolver for VPN clients
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${AGH_USER}
Group=${AGH_USER}
ExecStart=${AGH_BIN} --no-check-update --work-dir ${AGH_DIR} --config ${AGH_CONF}
WorkingDirectory=${AGH_DIR}
Restart=always
RestartSec=10
# A resolver is internet-facing by nature; give it as little of the host as it can
# do its job with.
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=${AGH_DIR}
ProtectHome=true
PrivateTmp=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictNamespaces=true
RestrictRealtime=true
LockPersonality=true
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
UNIT_EOF
fi

run systemctl daemon-reload
run systemctl enable AdGuardHome
run systemctl restart AdGuardHome

# Verify it actually came up before anything is pointed at it. Switching the host's
# resolver to a service that failed to start is how you lose a remote box.
if [[ "$DRY_RUN" != "1" ]]; then
  # "active" is not enough on its own. With Restart=always, a daemon that dies on a
  # port collision spends its life being restarted, and `is-active` polled once a
  # second can land in the window between spawn and exit and call that success. The
  # admin port is the honest test: nothing else on this node serves it, and AdGuard
  # only reaches it after every DNS listener has bound.
  AGH_SERVING=0
  for _ in $(seq 1 20); do
    sleep 1
    if curl -fsS --max-time 2 -o /dev/null "http://${TUNNEL_IP}:${UI_PORT}/" 2>/dev/null; then
      AGH_SERVING=1
      break
    fi
  done
  if [[ "$AGH_SERVING" != "1" ]]; then
    say ""
    journalctl -u AdGuardHome -n 30 --no-pager || true
    say ""
    die "AdGuard Home is not serving ${TUNNEL_IP}:${UI_PORT} — see the log above; nothing else has been changed, your DNS is untouched"
  fi
  info "service is running and serving ${TUNNEL_IP}:${UI_PORT}"

  # A real query through the new resolver, before the host depends on it. This runs
  # after the admin-port check for a reason: on a node where something else already
  # answers on 53, a query to the tunnel address is answered by *that*, and this test
  # passed against a resolver the script had not installed.
  if command -v dig >/dev/null 2>&1; then
    dig +short +timeout=5 @"${TUNNEL_IP}" example.com >/dev/null 2>&1 \
      || die "the resolver is up but did not answer a query — leaving your DNS untouched"
    info "test query answered"
  else
    warn "dig not installed; skipped the resolution test (install dnsutils to enable it)"
  fi
fi

# ---------------------------------------------------------------------------
# Firewall
# ---------------------------------------------------------------------------
if [[ "$DO_FIREWALL" == "1" ]]; then
  step "Firewall rules"

  if command -v nft >/dev/null 2>&1; then
    if [[ "$DRY_RUN" == "1" ]]; then
      info "[dry-run] would create nft tables ${NFT_TABLE} / ${NFT_NAT_TABLE}"
    else
      nft delete table "inet ${NFT_TABLE}" 2>/dev/null || true
      nft -f - <<NFT
table inet ${NFT_TABLE} {
  chain input {
    type filter hook input priority -10; policy accept;
    iif lo accept
    # The tunnel may use them; the internet may not. Priority -10 puts this ahead
    # of the app's own table (priority 0) so an open-resolver probe is dropped
    # regardless of what else is configured.
    iifname "${TUNNEL_IFACE}" ip saddr ${TUNNEL_SUBNET} udp dport 53 accept
    iifname "${TUNNEL_IFACE}" ip saddr ${TUNNEL_SUBNET} tcp dport 53 accept
    iifname "${TUNNEL_IFACE}" ip saddr ${TUNNEL_SUBNET} tcp dport ${UI_PORT} accept
    udp dport 53 drop
    tcp dport 53 drop
    tcp dport ${UI_PORT} drop
  }
  chain forward {
    type filter hook forward priority -10; policy accept;
    # DoT from a client cannot be redirected — the certificate would not match — so
    # it is refused. Without this, "Secure DNS" in a browser walks straight past the
    # filter and you would never know.
    iifname "${TUNNEL_IFACE}" ip saddr ${TUNNEL_SUBNET} tcp dport 853 reject with icmp type admin-prohibited
  }
}
NFT
      info "input: port 53 accepted from ${TUNNEL_SUBNET} only, dropped everywhere else"
      info "forward: client DoT (853) refused"

      case "$STRAY_DNS" in
        redirect)
          nft delete table "ip ${NFT_NAT_TABLE}" 2>/dev/null || true
          nft -f - <<NFT
table ip ${NFT_NAT_TABLE} {
  chain prerouting {
    type nat hook prerouting priority dstnat; policy accept;
    # A client that ignores the pushed resolver and dials 8.8.8.8 gets answered by
    # ours anyway. Redirecting rather than rejecting keeps hard-coded configs working
    # instead of turning a bypass into a support call.
    iifname "${TUNNEL_IFACE}" ip saddr ${TUNNEL_SUBNET} ip daddr != ${TUNNEL_IP} udp dport 53 dnat to ${TUNNEL_IP}:53
    iifname "${TUNNEL_IFACE}" ip saddr ${TUNNEL_SUBNET} ip daddr != ${TUNNEL_IP} tcp dport 53 dnat to ${TUNNEL_IP}:53
  }
}
NFT
          info "stray plaintext DNS redirected to ${TUNNEL_IP}"
          ;;
        reject)
          nft add rule inet "${NFT_TABLE}" forward iifname "${TUNNEL_IFACE}" ip saddr "${TUNNEL_SUBNET}" \
            ip daddr != "${TUNNEL_IP}" udp dport 53 reject
          nft add rule inet "${NFT_TABLE}" forward iifname "${TUNNEL_IFACE}" ip saddr "${TUNNEL_SUBNET}" \
            ip daddr != "${TUNNEL_IP}" tcp dport 53 reject with icmp type admin-prohibited
          info "stray plaintext DNS rejected"
          ;;
        allow) info "stray plaintext DNS left alone (--stray-dns allow)" ;;
      esac

      # nftables rules are runtime state; persist them if the distro has somewhere
      # to put them, otherwise say so rather than letting a reboot open port 53.
      if [[ -d /etc/nftables.d ]]; then
        nft list table "inet ${NFT_TABLE}" > /etc/nftables.d/ns-dns-filter.nft 2>/dev/null || true
        if [[ "$STRAY_DNS" == "redirect" ]]; then
          nft list table "ip ${NFT_NAT_TABLE}" >> /etc/nftables.d/ns-dns-filter.nft 2>/dev/null || true
        fi
        info "persisted to /etc/nftables.d/ns-dns-filter.nft"
      else
        warn "no /etc/nftables.d — these rules are runtime only and will not survive a reboot."
        warn "Persist them with:  nft list table inet ${NFT_TABLE} >> /etc/nftables.conf"
      fi
    fi
  elif command -v iptables >/dev/null 2>&1; then
    warn "nft not found; using iptables"
    IPT_RULES=(
      "-A INPUT -i ${TUNNEL_IFACE} -s ${TUNNEL_SUBNET} -p udp --dport 53 -j ACCEPT"
      "-A INPUT -i ${TUNNEL_IFACE} -s ${TUNNEL_SUBNET} -p tcp --dport 53 -j ACCEPT"
      "-A INPUT -i ${TUNNEL_IFACE} -s ${TUNNEL_SUBNET} -p tcp --dport ${UI_PORT} -j ACCEPT"
      "-A INPUT -p udp --dport 53 -j DROP"
      "-A INPUT -p tcp --dport 53 -j DROP"
      "-A INPUT -p tcp --dport ${UI_PORT} -j DROP"
      "-A FORWARD -i ${TUNNEL_IFACE} -s ${TUNNEL_SUBNET} -p tcp --dport 853 -j REJECT"
    )
    if [[ "$DRY_RUN" != "1" ]]; then : > "${STATE_DIR}/iptables-rules"; fi
    for rule in "${IPT_RULES[@]}"; do
      # shellcheck disable=SC2086
      run iptables -I ${rule#-A } 2>/dev/null || run iptables ${rule}
      [[ "$DRY_RUN" == "1" ]] || printf '%s\n' "$rule" >> "${STATE_DIR}/iptables-rules"
    done
    info "iptables rules added and recorded for --uninstall"
  else
    warn "neither nft nor iptables found — SKIPPING firewall rules."
    warn "Port 53 on this node is reachable from anywhere it is routable. Close it before"
    warn "leaving this box on the internet, or the resolver becomes an amplification relay."
  fi
else
  warn "--no-firewall: nothing restricts who can query port 53. Make sure something else does."
fi

# An accept in our chain is not the last word. nftables runs every base chain on a
# hook, so a later default-deny (ufw, or a distro firewall) can still drop a query
# our chain just accepted — and the failure looks like a broken resolver, not a
# firewall. Say so rather than letting it be debugged the hard way.
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -qi '^Status: active'; then
  say ""
  warn "ufw is active. Our accept does not override its default policy — allow the"
  warn "tunnel explicitly or clients will get no answers:"
  say  "      sudo ufw allow in on ${TUNNEL_IFACE} to any port 53 proto udp"
  say  "      sudo ufw allow in on ${TUNNEL_IFACE} to any port 53 proto tcp"
  say  "      sudo ufw allow in on ${TUNNEL_IFACE} to any port ${UI_PORT} proto tcp"
fi

# ---------------------------------------------------------------------------
# Point this host at the new resolver
# ---------------------------------------------------------------------------
if [[ "$DO_HOST_RESOLV" == "1" ]]; then
  step "Pointing this node at the resolver"

  # Chaining behind systemd-resolved rather than replacing it: resolved keeps its
  # stub on 127.0.0.53 and forwards to AdGuard on 127.0.0.1. Nothing fights over
  # port 53, /etc/resolv.conf does not change, and rollback is one file.
  if systemctl is-active --quiet systemd-resolved 2>/dev/null; then
    backup_file /etc/systemd/resolved.conf
    if [[ "$DRY_RUN" == "1" ]]; then
      info "[dry-run] would set systemd-resolved DNS=127.0.0.1"
    else
      mkdir -p /etc/systemd/resolved.conf.d
      cat > /etc/systemd/resolved.conf.d/ns-dns-filter.conf <<RESOLVED
# Written by scripts/setup-dns-filter.sh. Forward everything to AdGuard Home on
# loopback; it does the filtering and the encrypted upstream hop.
[Resolve]
DNS=127.0.0.1
FallbackDNS=
Domains=~.
DNSStubListener=yes
RESOLVED
      systemctl restart systemd-resolved
      info "systemd-resolved now forwards to 127.0.0.1"
    fi
  else
    backup_file /etc/resolv.conf
    if [[ "$DRY_RUN" == "1" ]]; then
      info "[dry-run] would write nameserver 127.0.0.1 to /etc/resolv.conf"
    else
      printf 'nameserver 127.0.0.1\noptions edns0 trust-ad\n' > /etc/resolv.conf
      info "/etc/resolv.conf now points at 127.0.0.1"
    fi
  fi

  if [[ "$DRY_RUN" != "1" ]] && command -v getent >/dev/null 2>&1; then
    if getent hosts example.com >/dev/null 2>&1; then
      info "host name resolution still works"
    else
      warn "host resolution failed - run '$0 --uninstall' to restore the previous configuration"
    fi
  fi
fi

# ---------------------------------------------------------------------------
# Tell Network Sentinel about it
# ---------------------------------------------------------------------------
step "Registering the resolver with Network Sentinel"

# DnsHygieneMonitor treats queries to anything outside ApprovedResolvers as a hijack.
# Installing a resolver without telling the app produces a High alert per client.
TARGET_USER="${SUDO_USER:-}"
if [[ -n "$TARGET_USER" ]]; then
  USER_HOME="$(getent passwd "$TARGET_USER" | cut -d: -f6)"
  SETTINGS="${USER_HOME}/.local/share/NetworkSentinel/settings.json"
  if [[ -f "$SETTINGS" ]]; then
    if pgrep -u "$TARGET_USER" -f 'NetworkSentinel' >/dev/null 2>&1; then
      warn "Network Sentinel is running — it would overwrite settings.json on exit."
      say  "  Set these by hand instead:"
      say  "      Settings -> DNS hygiene -> Approved resolvers:  ${TUNNEL_IP}, 127.0.0.1"
      say  "      Settings -> DNS filtering -> Filtering resolver: http://${TUNNEL_IP}:${UI_PORT}"
    elif [[ "$DRY_RUN" == "1" ]]; then
      info "[dry-run] would set DnsApprovedResolvers in ${SETTINGS}"
    else
      backup_file "$SETTINGS"
      if python3 -c '
import json, sys
path, ip, ui_port, user, password = sys.argv[1:6]
with open(path) as fh:
    cfg = json.load(fh)
cfg["DnsApprovedResolvers"] = f"{ip},127.0.0.1"
cfg["DnsHygieneEnabled"] = True
# Points the in-app DNS filtering switch at this resolver. Without the address the
# switch has nothing to control and says so rather than pretending to work.
cfg["DnsFilterUrl"] = f"http://{ip}:{ui_port}"
if user:
    cfg["DnsFilterUsername"] = user
    cfg["DnsFilterPassword"] = password
with open(path, "w") as fh:
    json.dump(cfg, fh, indent=2)
' "$SETTINGS" "$TUNNEL_IP" "$UI_PORT" "$([[ -n "$AGH_API_PASS" ]] && printf admin)" "$AGH_API_PASS"; then
        info "approved resolvers set, DNS hygiene enabled, filtering switch pointed at http://${TUNNEL_IP}:${UI_PORT}"
      else
        warn "could not update settings.json - set the approved resolvers in the UI"
      fi
      chown "${TARGET_USER}:" "$SETTINGS" 2>/dev/null || true
    fi
  else
    say "  No settings.json yet. After first launch, set:"
    say "      Settings -> DNS hygiene -> Approved resolvers:  ${TUNNEL_IP}, 127.0.0.1"
    say "      Settings -> DNS filtering -> Filtering resolver: http://${TUNNEL_IP}:${UI_PORT}"
  fi
else
  say "  Set Settings -> DNS hygiene -> Approved resolvers:  ${TUNNEL_IP}, 127.0.0.1"
  say "  Set Settings -> DNS filtering -> Filtering resolver: http://${TUNNEL_IP}:${UI_PORT}"
fi

# ---------------------------------------------------------------------------
# What is left for you to do
# ---------------------------------------------------------------------------
step "Done — one manual step left"

say ""
say "Point your clients at the resolver. Nothing filters until you do:"
say ""
if [[ -d /etc/wireguard ]]; then
  say "  WireGuard — in each CLIENT config, under [Interface]:"
  say ""
  say "      DNS = ${TUNNEL_IP}"
  say ""
  say "  and make sure the client's AllowedIPs covers ${TUNNEL_IP} (0.0.0.0/0 does)."
else
  say "  strongSwan/IPsec — in ipsec.conf on this node, in the connection block:"
  say ""
  say "      rightdns=${TUNNEL_IP}"
  say ""
  say "  then: ipsec reload"
fi
say ""
say "Then reconnect a client and check it:"
say ""
say "    dig @${TUNNEL_IP} example.com          # should answer normally"
say "    dig @${TUNNEL_IP} doubleclick.net      # should come back NXDOMAIN"
say ""
if [[ -n "$AGH_HASH" ]]; then
  say "Web UI:  http://${TUNNEL_IP}:${UI_PORT}   (user 'admin', the password you set)"
else
  say "Web UI:  http://${TUNNEL_IP}:${UI_PORT}   — finish the setup wizard there to set a password"
fi
say "Reachable over the tunnel only; the firewall drops it from everywhere else."
say ""
say "Filtering can be switched on and off from Network Sentinel itself — Settings ->"
say "DNS filtering, in the desktop app, the TUI and the web console. That switches"
say "filtering only: the resolver keeps answering, so no client loses name resolution."
say ""
say "Undo everything:   sudo $0 --uninstall"
say "Backups:           ${BACKUP_DIR}"
say ""
say "Worth knowing: this blocks by NAME. Malware that dials a hard-coded IP makes no"
say "DNS query and passes straight through — that gap is what Network Sentinel's"
say "threat-intel feeds cover, so keep both on."
