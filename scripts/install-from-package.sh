#!/usr/bin/env bash
# Install Network Sentinel from an extracted package directory.
#
# Usage:
#   sudo ./install.sh                     # system-wide → /usr/local
#   ./install.sh --user                   # user install → ~/.local
#   sudo ./install.sh --prefix /opt
#   sudo ./install.sh --web-service       # + systemd web UI on port 18765
#   sudo ./install.sh --web-service --port 18765
#   ./install.sh --user --web-service     # user systemd unit
#
set -euo pipefail

PKG_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_SRC="${PKG_ROOT}/app"
SYSTEMD_SRC="${PKG_ROOT}/systemd"

if [[ ! -f "${APP_SRC}/NetworkSentinel" ]]; then
  echo "error: missing app/NetworkSentinel — extract the tarball and run install.sh from inside it." >&2
  exit 1
fi
# Packages built on a Windows checkout can lose the exec bit — restore it.
chmod +x "${APP_SRC}/NetworkSentinel" 2>/dev/null || true

MODE="system"
PREFIX=""
WEB_SERVICE=0
WEB_PORT=18765
SERVICE_USER=""
NO_DESKTOP=0
DESKTOP_SHORTCUT=0

usage() {
  cat <<'EOF'
Install Network Sentinel from this package.

  sudo ./install.sh                         System-wide (/usr/local)
  ./install.sh --user                       User install (~/.local)
  sudo ./install.sh --prefix /opt           Custom prefix
  sudo ./install.sh --web-service           Also install systemd web UI service
  sudo ./install.sh --web-service --port N  Web UI on fixed port (default 18765)
  ./install.sh --user --web-service         User-level systemd web service

  --service-user NAME   Run the web service as this user (default: invoking user)
  --no-desktop          Skip .desktop menu entry
  --desktop-shortcut    Also drop an icon on ~/Desktop (opt-in; desktops only)
  -h, --help            Show this help

After --web-service:
  sudo systemctl enable --now networksentinel-web
  Open http://SERVER:18765/  (create master password on first visit)
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --user|-u) MODE="user"; shift ;;
    --prefix)
      PREFIX="${2:?--prefix requires a path}"
      MODE="custom"
      shift 2
      ;;
    --web-service|--service|-w)
      WEB_SERVICE=1
      shift
      ;;
    --port)
      WEB_PORT="${2:?--port requires a number}"
      if ! [[ "$WEB_PORT" =~ ^[0-9]+$ ]] || (( WEB_PORT < 1 || WEB_PORT > 65535 )); then
        echo "error: invalid port: $WEB_PORT" >&2
        exit 1
      fi
      shift 2
      ;;
    --service-user)
      SERVICE_USER="${2:?--service-user requires a name}"
      shift 2
      ;;
    --no-desktop) NO_DESKTOP=1; shift ;;
    --desktop-shortcut) DESKTOP_SHORTCUT=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage >&2; exit 1 ;;
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

if [[ "$MODE" != "user" && "$(id -u)" -ne 0 && "$MODE" == "custom" ]]; then
  if [[ ! -w "$(dirname "$PREFIX")" && ! -w "$PREFIX" ]]; then
    echo "Custom prefix may need root: sudo ./install.sh --prefix $PREFIX" >&2
  fi
fi

LIBDIR="${PREFIX}/lib/networksentinel"
BINDIR="${PREFIX}/bin"
DOCDIR="${PREFIX}/share/doc/networksentinel"
META="${LIBDIR}/.install-meta"

# Who should own the web service / data dir
if [[ -z "$SERVICE_USER" ]]; then
  if [[ -n "${SUDO_USER:-}" && "${SUDO_USER}" != "root" ]]; then
    SERVICE_USER="$SUDO_USER"
  elif [[ "$(id -u)" -eq 0 ]]; then
    SERVICE_USER="root"
  else
    SERVICE_USER="$(id -un)"
  fi
fi

if ! id "$SERVICE_USER" &>/dev/null; then
  echo "error: service user '$SERVICE_USER' does not exist" >&2
  exit 1
fi
SERVICE_GROUP="$(id -gn "$SERVICE_USER")"
SERVICE_HOME="$(getent passwd "$SERVICE_USER" | cut -d: -f6)"
if [[ -z "$SERVICE_HOME" ]]; then
  SERVICE_HOME="/home/${SERVICE_USER}"
fi
DATA_DIR="${SERVICE_HOME}/.local/share/NetworkSentinel"

echo "Installing Network Sentinel"
echo "  mode    : $MODE"
echo "  app     : $LIBDIR"
echo "  bin     : $BINDIR"
echo "  user    : $SERVICE_USER (data → $DATA_DIR)"
if [[ "$WEB_SERVICE" -eq 1 ]]; then
  echo "  web     : systemd service on port $WEB_PORT"
fi

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
SERVICE_USER=${SERVICE_USER}
WEB_SERVICE=${WEB_SERVICE}
WEB_PORT=${WEB_PORT}
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

# Convenience: web mode with optional default port from env file
cat > "${BINDIR}/networksentinel-web" <<EOF
#!/usr/bin/env bash
set -euo pipefail
APP="${LIBDIR}/NetworkSentinel"
PORT="\${NETWORKSENTINEL_WEB_PORT:-}"
if [[ -z "\$PORT" ]]; then
  for f in /etc/networksentinel/web.env "\${XDG_CONFIG_HOME:-\$HOME/.config}/networksentinel/web.env" "\$HOME/.config/networksentinel/web.env"; do
    if [[ -f "\$f" ]]; then
      # shellcheck disable=SC1090
      source "\$f"
      PORT="\${WEB_PORT:-}"
      break
    fi
  done
fi
PORT="\${PORT:-18765}"
if [[ ! -x "\$APP" ]]; then
  echo "Network Sentinel binary missing: \$APP" >&2
  exit 127
fi
exec "\$APP" -w "\$PORT"
EOF
chmod +x "${BINDIR}/networksentinel-web"

# Uninstall entry point
cat > "${BINDIR}/networksentinel-uninstall" <<'UNINSTALL_EOF'
#!/usr/bin/env bash
set -euo pipefail
META="__META__"
if [[ ! -f "$META" ]]; then
  echo "No install metadata at $META — nothing to uninstall?" >&2
  exit 1
fi
# shellcheck disable=SC1090
source "$META"
if [[ "${MODE}" == "system" && "$(id -u)" -ne 0 ]]; then
  echo "System uninstall needs root: sudo networksentinel-uninstall" >&2
  exit 1
fi

echo "Stopping web service (if any)…"
if [[ "${MODE:-}" == "user" ]]; then
  systemctl --user disable --now networksentinel-web.service 2>/dev/null || true
  rm -f "${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user/networksentinel-web.service" 2>/dev/null || true
  systemctl --user daemon-reload 2>/dev/null || true
else
  if [[ "$(id -u)" -eq 0 ]]; then
    systemctl disable --now networksentinel-web.service 2>/dev/null || true
    rm -f /etc/systemd/system/networksentinel-web.service
    systemctl daemon-reload 2>/dev/null || true
  fi
fi

echo "Removing Network Sentinel from ${PREFIX}"
rm -f "${BINDIR}/networksentinel" "${BINDIR}/networksentinel-web" "${BINDIR}/networksentinel-uninstall"
rm -rf "${LIBDIR}" "${DOCDIR}"
# Optional system env (keep by default? remove if empty dir)
if [[ "$(id -u)" -eq 0 ]]; then
  rm -f /etc/networksentinel/web.env 2>/dev/null || true
  rmdir /etc/networksentinel 2>/dev/null || true
fi
rm -f "${XDG_CONFIG_HOME:-$HOME/.config}/networksentinel/web.env" 2>/dev/null || true
rmdir "${XDG_CONFIG_HOME:-$HOME/.config}/networksentinel" 2>/dev/null || true

# Desktop entry
rm -f /usr/local/share/applications/networksentinel.desktop 2>/dev/null || true
rm -f "${XDG_DATA_HOME:-$HOME/.local/share}/applications/networksentinel.desktop" 2>/dev/null || true

echo "Done. User data left in ~/.local/share/NetworkSentinel (remove manually if you want)."
UNINSTALL_EOF
# Inject meta path (avoid expansion issues in heredoc)
sed -i "s|__META__|${META}|g" "${BINDIR}/networksentinel-uninstall"
chmod +x "${BINDIR}/networksentinel-uninstall"

if [[ -f "${PKG_ROOT}/README-INSTALL.txt" ]]; then
  cp "${PKG_ROOT}/README-INSTALL.txt" "${DOCDIR}/"
fi

# Desktop entry (optional; harmless on servers)
if [[ "$NO_DESKTOP" -eq 0 ]]; then
  DESKTOP_SRC="${PKG_ROOT}/networksentinel.desktop"
  if [[ -f "$DESKTOP_SRC" ]]; then
    if [[ "$MODE" == "user" ]]; then
      APP_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/applications"
    else
      APP_DIR="${PREFIX}/share/applications"
    fi
    mkdir -p "$APP_DIR"
    sed "s|^Exec=.*|Exec=${BINDIR}/networksentinel|" "$DESKTOP_SRC" > "${APP_DIR}/networksentinel.desktop" 2>/dev/null \
      || cp "$DESKTOP_SRC" "${APP_DIR}/networksentinel.desktop"

    # Opt-in desktop icon. Installs for the invoking user even under sudo —
    # root's Desktop is not where anyone would look for it.
    if [[ "$DESKTOP_SHORTCUT" -eq 1 ]]; then
      shortcut_home="$HOME"
      [[ -n "${SUDO_USER:-}" ]] && shortcut_home="$(getent passwd "$SUDO_USER" | cut -d: -f6)"
      # Honour a localised or relocated Desktop (xdg-user-dirs), else ~/Desktop.
      desktop_dir="$(sudo -u "${SUDO_USER:-$USER}" xdg-user-dir DESKTOP 2>/dev/null || true)"
      [[ -d "${desktop_dir:-}" ]] || desktop_dir="${shortcut_home}/Desktop"
      if [[ -d "$desktop_dir" ]]; then
        shortcut="${desktop_dir}/Network Sentinel.desktop"
        cp "${APP_DIR}/networksentinel.desktop" "$shortcut"
        # GNOME/COSMIC refuse to launch a desktop file that is not executable
        # and not marked trusted; without both it shows as an inert text file.
        chmod +x "$shortcut"
        [[ -n "${SUDO_USER:-}" ]] && chown "$SUDO_USER" "$shortcut" 2>/dev/null || true
        sudo -u "${SUDO_USER:-$USER}" gio set "$shortcut" metadata::trusted true 2>/dev/null || true
        echo "  shortcut: $shortcut"
      else
        echo "  note: no Desktop directory found — skipped --desktop-shortcut" >&2
      fi
    fi
  fi
fi

install_web_service() {
  local unit_src unit_dst env_dir env_file
  mkdir -p "$DATA_DIR"
  if [[ "$MODE" == "user" ]]; then
    # User systemd
    unit_dst="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user/networksentinel-web.service"
    env_dir="${XDG_CONFIG_HOME:-$HOME/.config}/networksentinel"
    env_file="${env_dir}/web.env"
    mkdir -p "$(dirname "$unit_dst")" "$env_dir"
  else
    if [[ "$(id -u)" -ne 0 ]]; then
      echo "error: system web service needs root (sudo ./install.sh --web-service)" >&2
      exit 1
    fi
    unit_dst="/etc/systemd/system/networksentinel-web.service"
    env_dir="/etc/networksentinel"
    env_file="${env_dir}/web.env"
    mkdir -p "$env_dir"
  fi

  cat > "$env_file" <<EOF
# Network Sentinel web UI — edited by install.sh; safe to change WEB_PORT.
WEB_PORT=${WEB_PORT}
EOF
  chmod 644 "$env_file"

  # Prefer packaged unit template; fall back to inline.
  if [[ -f "${SYSTEMD_SRC}/networksentinel-web.service" ]]; then
    sed \
      -e "s|REPLACE_USER|${SERVICE_USER}|g" \
      -e "s|REPLACE_GROUP|${SERVICE_GROUP}|g" \
      -e "s|REPLACE_LIBDIR|${LIBDIR}|g" \
      -e "s|REPLACE_BINDIR|${BINDIR}|g" \
      -e "s|REPLACE_DATA_DIR|${DATA_DIR}|g" \
      -e "s|REPLACE_ENV_FILE|${env_file}|g" \
      "${SYSTEMD_SRC}/networksentinel-web.service" > "$unit_dst"
  else
    cat > "$unit_dst" <<EOF
[Unit]
Description=Network Sentinel headless web console
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${SERVICE_USER}
Group=${SERVICE_GROUP}
EnvironmentFile=-${env_file}
WorkingDirectory=${LIBDIR}
ExecStart=${BINDIR}/networksentinel -w \${WEB_PORT}
Restart=on-failure
RestartSec=5
TimeoutStopSec=20
PrivateTmp=true
ReadWritePaths=${DATA_DIR}

[Install]
WantedBy=multi-user.target
EOF
  fi

  # User units run as the session user; strip User/Group and use default.target.
  if [[ "$MODE" == "user" ]]; then
    sed -i '/^User=/d;/^Group=/d' "$unit_dst"
    sed -i 's/WantedBy=multi-user.target/WantedBy=default.target/' "$unit_dst"
  fi

  # Ensure service user can write data dir
  if [[ "$(id -u)" -eq 0 ]]; then
    mkdir -p "$DATA_DIR"
    chown -R "${SERVICE_USER}:${SERVICE_GROUP}" "$DATA_DIR" 2>/dev/null || true
  fi

  if [[ "$MODE" == "user" ]]; then
    systemctl --user daemon-reload
    systemctl --user enable networksentinel-web.service
    # restart (not enable --now): an already-running old version must be replaced
    systemctl --user restart networksentinel-web.service
    echo
    echo "User web service started."
    echo "  systemctl --user status networksentinel-web"
    echo "  journalctl --user -u networksentinel-web -f"
    # linger so it survives logout on servers
    if command -v loginctl &>/dev/null && [[ "$(id -u)" -ne 0 ]]; then
      if ! loginctl show-user "$(id -un)" 2>/dev/null | grep -q 'Linger=yes'; then
        echo
        echo "Tip: keep the service after logout:"
        echo "  sudo loginctl enable-linger $(id -un)"
      fi
    fi
  else
    systemctl daemon-reload
    systemctl enable networksentinel-web.service
    # restart (not enable --now): an already-running old version must be replaced
    systemctl restart networksentinel-web.service
    echo
    echo "Web service started."
    echo "  systemctl status networksentinel-web"
    echo "  journalctl -u networksentinel-web -f"
  fi
}

if [[ "$WEB_SERVICE" -eq 1 ]]; then
  install_web_service
else
  # Upgrade path without --web-service: a previously installed web service is
  # still running the OLD binary from memory — restart it onto the new files.
  if [[ "$MODE" == "user" ]]; then
    if systemctl --user is-active networksentinel-web.service &>/dev/null; then
      systemctl --user restart networksentinel-web.service || true
      echo "Restarted running networksentinel-web (user) with the new version."
    fi
  else
    if systemctl is-active networksentinel-web.service &>/dev/null; then
      systemctl restart networksentinel-web.service || true
      echo "Restarted running networksentinel-web with the new version."
    fi
  fi
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
echo "Commands:"
echo "  networksentinel --tui          # terminal UI (SSH)"
echo "  networksentinel -w             # headless web UI (auto free port)"
echo "  networksentinel-web            # web UI on configured port (${WEB_PORT})"
echo "  networksentinel --help"
echo "  networksentinel-uninstall"
if [[ "$WEB_SERVICE" -eq 1 ]]; then
  echo
  echo "Web console:"
  echo "  http://$(hostname -I 2>/dev/null | awk '{print $1}'):${WEB_PORT}/"
  echo "  http://127.0.0.1:${WEB_PORT}/"
  echo "  First visit: create a master password in the browser."
  echo "  Later visits: enter that master password."
fi
echo
echo "Firewall: install policykit-1 or use sudo so IP block actions can elevate."
echo "Data: ${DATA_DIR}"
