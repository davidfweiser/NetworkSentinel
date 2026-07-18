#!/usr/bin/env bash
# Install Network Sentinel from an extracted package directory.
# Usage:
#   sudo ./install.sh              # system-wide → /usr/local
#   ./install.sh --user            # user install → ~/.local
#   sudo ./install.sh --prefix /opt  # custom prefix (app → PREFIX/lib/networksentinel)
set -euo pipefail

PKG_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_SRC="${PKG_ROOT}/app"

if [[ ! -x "${APP_SRC}/NetworkSentinel" ]]; then
  echo "error: missing app/NetworkSentinel — extract the tarball and run install.sh from inside it." >&2
  exit 1
fi

MODE="system"
PREFIX=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --user|-u) MODE="user"; shift ;;
    --prefix)
      PREFIX="${2:?--prefix requires a path}"
      MODE="custom"
      shift 2
      ;;
    -h|--help)
      cat <<'EOF'
Install Network Sentinel from this package.

  sudo ./install.sh           System-wide (/usr/local)
  ./install.sh --user         User install (~/.local)
  sudo ./install.sh --prefix /opt
EOF
      exit 0
      ;;
    *) echo "Unknown option: $1" >&2; exit 1 ;;
  esac
done

if [[ "$MODE" == "user" ]]; then
  PREFIX="${HOME}/.local"
elif [[ "$MODE" == "custom" ]]; then
  :
else
  PREFIX="/usr/local"
  if [[ "$(id -u)" -ne 0 ]]; then
    echo "System install needs root. Use:  sudo ./install.sh   or   ./install.sh --user" >&2
    exit 1
  fi
fi

LIBDIR="${PREFIX}/lib/networksentinel"
BINDIR="${PREFIX}/bin"
DOCDIR="${PREFIX}/share/doc/networksentinel"
META="${LIBDIR}/.install-meta"

echo "Installing Network Sentinel"
echo "  mode : $MODE"
echo "  app  : $LIBDIR"
echo "  bin  : $BINDIR"

mkdir -p "$LIBDIR" "$BINDIR" "$DOCDIR"

# Refresh app payload
find "$LIBDIR" -mindepth 1 -maxdepth 1 -exec rm -rf {} + 2>/dev/null || true
cp -a "${APP_SRC}/." "$LIBDIR/"
chmod +x "$LIBDIR/NetworkSentinel"

# Record layout for uninstall
cat > "$META" <<EOF
MODE=${MODE}
PREFIX=${PREFIX}
LIBDIR=${LIBDIR}
BINDIR=${BINDIR}
DOCDIR=${DOCDIR}
INSTALLED_AT=$(date -u +%Y-%m-%dT%H:%M:%SZ)
EOF

# Launcher on PATH
cat > "${BINDIR}/networksentinel" <<EOF
#!/usr/bin/env bash
set -euo pipefail
APP="${LIBDIR}/NetworkSentinel"
if [[ ! -x "\$APP" ]]; then
  echo "Network Sentinel binary missing: \$APP" >&2
  echo "Reinstall or run: networksentinel-uninstall" >&2
  exit 127
fi
exec "\$APP" "\$@"
EOF
chmod +x "${BINDIR}/networksentinel"

# Uninstall entry point
cat > "${BINDIR}/networksentinel-uninstall" <<EOF
#!/usr/bin/env bash
set -euo pipefail
META="${META}"
if [[ ! -f "\$META" ]]; then
  echo "No install metadata at \$META — nothing to uninstall?" >&2
  exit 1
fi
# shellcheck disable=SC1090
source "\$META"
if [[ "\${MODE}" == "system" && "\$(id -u)" -ne 0 ]]; then
  echo "System uninstall needs root: sudo networksentinel-uninstall" >&2
  exit 1
fi
echo "Removing Network Sentinel from \${PREFIX}"
rm -f "\${BINDIR}/networksentinel" "\${BINDIR}/networksentinel-uninstall"
rm -rf "\${LIBDIR}" "\${DOCDIR}"
echo "Done. User data left in ~/.local/share/NetworkSentinel (remove manually if you want)."
EOF
chmod +x "${BINDIR}/networksentinel-uninstall"

if [[ -f "${PKG_ROOT}/README-INSTALL.txt" ]]; then
  cp "${PKG_ROOT}/README-INSTALL.txt" "${DOCDIR}/"
fi

echo
echo "Installed."
if [[ "$MODE" == "user" ]]; then
  case ":${PATH}:" in
    *":${BINDIR}:"*) ;;
    *)
      echo
      echo "Add to PATH if needed:"
      echo "  export PATH=\"${BINDIR}:\$PATH\""
      ;;
  esac
fi
echo
echo "  networksentinel --tui     # terminal UI (servers / SSH)"
echo "  networksentinel --help"
echo "  networksentinel-uninstall"
