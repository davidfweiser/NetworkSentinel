#!/usr/bin/env bash
# Uninstall when still inside the package tree, or after install via networksentinel-uninstall.
# Prefer:  networksentinel-uninstall
set -euo pipefail

MODE="system"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --user|-u) MODE="user"; shift ;;
    --prefix)
      PREFIX="${2:?}"
      if [[ -x "${PREFIX}/bin/networksentinel-uninstall" ]]; then
        exec "${PREFIX}/bin/networksentinel-uninstall"
      fi
      echo "No install found under $PREFIX" >&2
      exit 1
      ;;
    -h|--help)
      echo "Usage: sudo ./uninstall.sh | ./uninstall.sh --user"
      echo "Prefer: networksentinel-uninstall (after install)"
      exit 0
      ;;
    *) shift ;;
  esac
done

if [[ "$MODE" == "user" ]]; then
  HELPER="${HOME}/.local/bin/networksentinel-uninstall"
else
  HELPER="/usr/local/bin/networksentinel-uninstall"
fi

if [[ -x "$HELPER" ]]; then
  exec "$HELPER"
fi

echo "Could not find $HELPER — is Network Sentinel installed?" >&2
echo "Try: networksentinel-uninstall" >&2
exit 1
