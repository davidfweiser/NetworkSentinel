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
# Non-interactive (this is how the desktop app's "Issue certificate" button runs it —
# there is no terminal to answer prompts on, so anything missing is an error, not a read):
#   NS_ASSUME_YES=1 NS_ACME_EMAIL=you@example.com ./scripts/issue-duckdns-cert.sh myhost
#
# Renewal: acme.sh installs its own cron entry. The console re-reads the files when
# they change, so a renewal applies without restarting it.
set -euo pipefail

# No TTY means nothing can answer a prompt; treat it as non-interactive so a
# missing value fails with a message instead of hanging on a read forever.
NS_ASSUME_YES="${NS_ASSUME_YES:-0}"
[[ -t 0 ]] || NS_ASSUME_YES=1
interactive() { [[ "$NS_ASSUME_YES" != "1" ]]; }

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
  interactive || die "no DuckDNS subdomain — pass it as an argument or save one first"
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
  interactive || die "no DuckDNS token saved — set one in Settings or with --set-duckdns"
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

  if interactive; then
    read -r -p "Install it now from https://get.acme.sh? [y/N] " reply
    [[ "$reply" =~ ^[Yy]$ ]] || die "acme.sh is required — install it and re-run"
  else
    say "Installing it now (NS_ASSUME_YES)."
  fi

  ACCOUNT_EMAIL="${NS_ACME_EMAIL:-}"
  if [[ -z "$ACCOUNT_EMAIL" ]]; then
    # Let's Encrypt registers the account against this address; there is no way to
    # skip it on first run, so fail with the fix rather than registering a fake one.
    interactive || die "acme.sh is not installed yet and no email was given — set NS_ACME_EMAIL to register the Let's Encrypt account"
    read -r -p "Email for Let's Encrypt expiry notices: " ACCOUNT_EMAIL
  fi
  [[ -n "$ACCOUNT_EMAIL" ]] || die "an email is required to register an ACME account"

  curl -fsSL https://get.acme.sh | sh -s "email=${ACCOUNT_EMAIL}"
  [[ -x "$ACME" ]] || die "acme.sh install did not produce ${ACME}"
fi

say ""
say "Issuing a certificate for ${FQDN} (DNS-01 via the DuckDNS API)…"
say "DuckDNS TXT records take a couple of minutes to propagate — this is not stuck."
say ""

# --dnssleep: DuckDNS is slower to publish TXT records than acme.sh's default probe allows.
# NS_FORCE_RENEW re-issues a certificate that is still current, which Let's Encrypt
# rate-limits — so it is opt-in rather than the default.
ISSUE_ARGS=(--issue --dns dns_duckdns -d "$FQDN" --server letsencrypt --dnssleep 120 --keylength ec-256)
# An `if`, not `[[ ]] && …`: under `set -e` a false test on the last command of an
# AND-list aborts the script.
if [[ "${NS_FORCE_RENEW:-0}" == "1" ]]; then
  ISSUE_ARGS+=(--force)
fi

set +e
"$ACME" "${ISSUE_ARGS[@]}"
ISSUE_RC=$?
set -e

# acme.sh exits 2 when the certificate is still valid and it skipped the renewal.
# Nothing failed — the certificate exists, and the console still needs it copied
# into place, so carry on to --install-cert instead of treating this as an error.
if [[ $ISSUE_RC -eq 2 ]]; then
  say ""
  say "Certificate is still current, so acme.sh skipped renewal — installing the existing one."
  say "Re-issue early with NS_FORCE_RENEW=1 (Let's Encrypt rate-limits this, so only when needed)."
elif [[ $ISSUE_RC -ne 0 ]]; then
  die "certificate issuance failed (see the acme.sh output above)"
fi

# --- Install where the console reads it ------------------------------------
mkdir -p "$TLS_DIR"
chmod 700 "$TLS_DIR"

CERT_FILE="${TLS_DIR}/${FQDN}.fullchain.cer"
KEY_FILE="${TLS_DIR}/${FQDN}.key"

"$ACME" --install-cert -d "$FQDN" --ecc \
  --fullchain-file "$CERT_FILE" \
  --key-file "$KEY_FILE"

chmod 600 "$KEY_FILE"

# Machine-readable result for the desktop app, which fills the two path fields in
# Settings from these lines. Only emitted when driven non-interactively, so the
# hand-run output stays prose.
if ! interactive; then
  printf 'NS_CERT_FILE=%s\n' "$CERT_FILE"
  printf 'NS_KEY_FILE=%s\n' "$KEY_FILE"
fi

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
