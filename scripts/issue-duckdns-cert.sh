#!/usr/bin/env bash
# Issue a free Let's Encrypt certificate for a duckdns.org hostname and install it
# where the Network Sentinel web console expects it.
#
# DNS-01 is used rather than HTTP-01: it proves control by writing a TXT record
# through the DuckDNS API, so nothing has to be reachable on port 80.
#
# Usage:
#   ./scripts/issue-duckdns-cert.sh                       # prompts for anything missing
#   ./scripts/issue-duckdns-cert.sh myhost                # subdomain as an argument
#   DuckDNS_Token=xxxx ./scripts/issue-duckdns-cert.sh myhost
#
# Renewal: acme.sh installs its own cron entry. The console re-reads the files when
# they change, so a renewal applies without restarting it.
set -euo pipefail

# Mirrors AppPaths.DataDirectory: XDG_DATA_HOME, else ~/.local/share.
DATA_DIR="${XDG_DATA_HOME:-${HOME}/.local/share}/NetworkSentinel"
TLS_DIR="${DATA_DIR}/tls"
DUCKDNS_JSON="${DATA_DIR}/duckdns.json"
ACME="${HOME}/.acme.sh/acme.sh"

say() { printf '%s\n' "$*"; }
die() { printf 'Error: %s\n' "$*" >&2; exit 1; }

# --- Subdomain -------------------------------------------------------------
DOMAIN_LABEL="${1:-}"

if [[ -z "$DOMAIN_LABEL" && -f "$DUCKDNS_JSON" ]]; then
  DOMAIN_LABEL="$(python3 -c '
import json, sys
try:
    print(json.load(open(sys.argv[1])).get("Domain", "").split(",")[0])
except Exception:
    print("")
' "$DUCKDNS_JSON" 2>/dev/null || true)"
  [[ -n "$DOMAIN_LABEL" ]] && say "Using subdomain from ${DUCKDNS_JSON}: ${DOMAIN_LABEL}"
fi

if [[ -z "$DOMAIN_LABEL" ]]; then
  read -r -p "DuckDNS subdomain (just the label, e.g. 'myhost'): " DOMAIN_LABEL
fi

# Accept myhost, myhost.duckdns.org, or a pasted URL.
DOMAIN_LABEL="${DOMAIN_LABEL#http://}"
DOMAIN_LABEL="${DOMAIN_LABEL#https://}"
DOMAIN_LABEL="${DOMAIN_LABEL%%/*}"
DOMAIN_LABEL="${DOMAIN_LABEL%.duckdns.org}"
[[ -n "$DOMAIN_LABEL" ]] || die "no subdomain given"
FQDN="${DOMAIN_LABEL}.duckdns.org"

# --- Token -----------------------------------------------------------------
if [[ -z "${DuckDNS_Token:-}" && -f "$DUCKDNS_JSON" ]]; then
  DuckDNS_Token="$(python3 -c '
import json, sys
try:
    print(json.load(open(sys.argv[1])).get("Token", ""))
except Exception:
    print("")
' "$DUCKDNS_JSON" 2>/dev/null || true)"
  [[ -n "${DuckDNS_Token:-}" ]] && say "Using the token already saved for the web console."
fi

if [[ -z "${DuckDNS_Token:-}" ]]; then
  read -r -s -p "DuckDNS token (hidden): " DuckDNS_Token
  echo
fi
[[ -n "${DuckDNS_Token:-}" ]] || die "no DuckDNS token given"
export DuckDNS_Token

# --- acme.sh ---------------------------------------------------------------
if [[ ! -x "$ACME" ]]; then
  say ""
  say "acme.sh is not installed (looked for ${ACME})."
  say "It is a shell ACME client; the installer writes to ~/.acme.sh and adds a renewal cron entry."
  read -r -p "Install it now from https://get.acme.sh? [y/N] " reply
  [[ "$reply" =~ ^[Yy]$ ]] || die "acme.sh is required — install it and re-run"

  read -r -p "Email for Let's Encrypt expiry notices: " ACCOUNT_EMAIL
  [[ -n "$ACCOUNT_EMAIL" ]] || die "an email is required to register an ACME account"
  curl -fsSL https://get.acme.sh | sh -s "email=${ACCOUNT_EMAIL}"
  [[ -x "$ACME" ]] || die "acme.sh install did not produce ${ACME}"
fi

say ""
say "Issuing a certificate for ${FQDN} (DNS-01 via the DuckDNS API)…"
say "DuckDNS TXT records take a couple of minutes to propagate — this is not stuck."
say ""

# --dnssleep: DuckDNS is slower to publish TXT records than acme.sh's default probe allows.
"$ACME" --issue \
  --dns dns_duckdns \
  -d "$FQDN" \
  --server letsencrypt \
  --dnssleep 120 \
  --keylength ec-256 || die "certificate issuance failed (see the acme.sh output above)"

# --- Install where the console reads it ------------------------------------
mkdir -p "$TLS_DIR"
chmod 700 "$TLS_DIR"

CERT_FILE="${TLS_DIR}/${FQDN}.fullchain.cer"
KEY_FILE="${TLS_DIR}/${FQDN}.key"

"$ACME" --install-cert -d "$FQDN" --ecc \
  --fullchain-file "$CERT_FILE" \
  --key-file "$KEY_FILE"

chmod 600 "$KEY_FILE"

say ""
say "Certificate installed:"
say "  cert: ${CERT_FILE}"
say "  key:  ${KEY_FILE}"
say ""
say "Start the console over HTTPS with:"
say "  networksentinel -w --https \\"
say "      --tls-cert \"${CERT_FILE}\" \\"
say "      --tls-key  \"${KEY_FILE}\""
say ""
say "Or set the same paths under Settings → Remote access to make it the default."
say ""
say "acme.sh renews automatically and rewrites these files; the console reloads them"
say "within a few minutes, so no restart is needed at renewal."
say ""
say "Reachability from outside your LAN still needs a router port-forward to this machine."
say "Forward only the HTTPS port, and use a long unique master password."
