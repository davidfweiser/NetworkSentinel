#!/usr/bin/env bash
# Build a portable, self-contained install tarball + one-file installer for servers.
# Usage:
#   ./scripts/package.sh              # linux-x64
#   ./scripts/package.sh linux-arm64  # Raspberry Pi / ARM servers
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

export PATH="${HOME}/.dotnet:${PATH}"
export DOTNET_ROOT="${DOTNET_ROOT:-${HOME}/.dotnet}"

RID="${1:-linux-x64}"
case "$RID" in
  linux-x64|linux-arm64|linux-musl-x64|linux-musl-arm64) ;;
  *)
    echo "Unsupported RID: $RID" >&2
    echo "Use: linux-x64 | linux-arm64 | linux-musl-x64 | linux-musl-arm64" >&2
    exit 1
    ;;
esac

VERSION="$(grep -oP '(?<=<Version>)[^<]+' NetworkSentinel.csproj | head -1)"
VERSION="${VERSION:-0.0.0}"
NAME="networksentinel-${VERSION}-${RID}"
DIST_DIR="${ROOT}/dist"
STAGE="${DIST_DIR}/${NAME}"
PUBLISH_DIR="${STAGE}/app"
OUT_TGZ="${DIST_DIR}/${NAME}.tar.gz"
OUT_RUN="${DIST_DIR}/${NAME}.install.sh"

echo "==> Network Sentinel ${VERSION}  RID=${RID}"
echo "==> Staging: ${STAGE}"

rm -rf "$STAGE"
mkdir -p "$PUBLISH_DIR"

echo "==> Publishing self-contained binary (no .NET runtime needed on target)…"
dotnet publish NetworkSentinel.csproj \
  -c Release \
  -r "$RID" \
  --self-contained true \
  -p:PublishSingleFile=false \
  -p:PublishReadyToRun=true \
  -p:DebugType=None \
  -p:DebugSymbols=false \
  -o "$PUBLISH_DIR"

chmod +x "$PUBLISH_DIR/NetworkSentinel"

# Install / uninstall helpers shipped inside the tarball
cp "$ROOT/scripts/install-from-package.sh" "$STAGE/install.sh"
cp "$ROOT/scripts/uninstall-from-package.sh" "$STAGE/uninstall.sh"
chmod +x "$STAGE/install.sh" "$STAGE/uninstall.sh"

# systemd unit + env example
mkdir -p "$STAGE/systemd"
cp "$ROOT/scripts/systemd/networksentinel-web.service" "$STAGE/systemd/"
cp "$ROOT/scripts/systemd/web.env.example" "$STAGE/systemd/"

# Optional desktop entry
if [[ -f "$ROOT/networksentinel.desktop" ]]; then
  cp "$ROOT/networksentinel.desktop" "$STAGE/"
fi

# Short README for operators
cat > "$STAGE/README-INSTALL.txt" <<EOF
Network Sentinel ${VERSION} (${RID})
====================================

Self-contained package — no .NET SDK/runtime required on the server.

────────────────────────────────────────
Quick install (recommended on a server)
────────────────────────────────────────

  tar xzf ${NAME}.tar.gz
  cd ${NAME}
  sudo ./install.sh --web-service

That installs the app under /usr/local and starts a systemd web UI on port 18765.

  Open:  http://YOUR_SERVER_IP:18765/
  First visit: create a master password
  Every later visit: enter that password

Other install options
---------------------
  sudo ./install.sh                          # app only (no systemd)
  sudo ./install.sh --web-service --port 18765
  ./install.sh --user                        # no root → ~/.local
  ./install.sh --user --web-service          # user systemd unit
  sudo ./install.sh --prefix /opt

One-file installer (if you have ${NAME}.install.sh)
---------------------------------------------------
  chmod +x ${NAME}.install.sh
  sudo ./${NAME}.install.sh --web-service

Run after install
-----------------
  networksentinel --tui          # terminal UI (SSH)
  networksentinel -w             # web UI, auto free port
  networksentinel-web            # web UI on configured port (default 18765)
  networksentinel --help

  systemctl status networksentinel-web
  journalctl -u networksentinel-web -f
  sudo systemctl restart networksentinel-web

Change web port
---------------
  sudoedit /etc/networksentinel/web.env     # set WEB_PORT=…
  sudo systemctl restart networksentinel-web

Uninstall
---------
  sudo networksentinel-uninstall
  # user install:  networksentinel-uninstall

Firewall notes
--------------
  - Prefer running as a normal user (the installer does this via sudo's SUDO_USER).
  - Blocking IPs elevates nft/iptables via pkexec or sudo.
  - On a headless server:  sudo apt install policykit-1   (or rely on sudo)

Data / settings / master password hash
--------------------------------------
  ~/.local/share/NetworkSentinel/
  web-master.json   # delete this file to reset the web master password
EOF

# Checksum of the app binary for sanity
(
  cd "$PUBLISH_DIR"
  sha256sum NetworkSentinel > SHA256SUMS 2>/dev/null || shasum -a 256 NetworkSentinel > SHA256SUMS
)

echo "==> Creating tarball…"
mkdir -p "$DIST_DIR"
tar -C "$DIST_DIR" -czf "$OUT_TGZ" "$NAME"

# Convenience checksum for the archive
(
  cd "$DIST_DIR"
  sha256sum "$(basename "$OUT_TGZ")" > "$(basename "$OUT_TGZ").sha256" 2>/dev/null \
    || shasum -a 256 "$(basename "$OUT_TGZ")" > "$(basename "$OUT_TGZ").sha256"
)

echo "==> Building one-file installer (${OUT_RUN})…"
# Self-extracting installer: bash header + embedded tar.gz
{
  cat <<'HEADER'
#!/usr/bin/env bash
# Network Sentinel self-extracting installer
# Usage:
#   sudo ./networksentinel-*-linux-x64.install.sh --web-service
#   ./networksentinel-*-linux-x64.install.sh --user
set -euo pipefail

ARGS=("$@")
for a in "${ARGS[@]+"${ARGS[@]}"}"; do
  case "$a" in
    -h|--help)
      cat <<'HELP'
Network Sentinel self-extracting installer

  sudo ./this.install.sh --web-service     Install + systemd web UI (port 18765)
  sudo ./this.install.sh                   Install app only
  ./this.install.sh --user                 User install (~/.local)
  ./this.install.sh --user --web-service
  sudo ./this.install.sh --web-service --port 18765

Same flags as install.sh inside the package.
HELP
      exit 0
      ;;
  esac
done

TMP="$(mktemp -d "${TMPDIR:-/tmp}/networksentinel-install.XXXXXX")"
cleanup() { rm -rf "$TMP"; }
trap cleanup EXIT

# Locate archive marker
ARCHIVE_LINE="$(awk '/^__ARCHIVE_BELOW__$/ {print NR + 1; exit 0;}' "$0")"
if [[ -z "$ARCHIVE_LINE" ]]; then
  echo "error: corrupt installer (missing archive marker)" >&2
  exit 1
fi

echo "==> Extracting package…"
tail -n "+${ARCHIVE_LINE}" "$0" | tar -xz -C "$TMP"

# Expect a single top-level directory
PKG_DIR="$(find "$TMP" -mindepth 1 -maxdepth 1 -type d | head -1)"
if [[ -z "$PKG_DIR" || ! -x "${PKG_DIR}/install.sh" ]]; then
  echo "error: package layout unexpected after extract" >&2
  exit 1
fi

echo "==> Running installer…"
cd "$PKG_DIR"
./install.sh "${ARGS[@]+"${ARGS[@]}"}"
exit 0
# Embedded tarball follows (do not execute past this marker)
__ARCHIVE_BELOW__
HEADER
  cat "$OUT_TGZ"
} > "$OUT_RUN"
chmod +x "$OUT_RUN"

(
  cd "$DIST_DIR"
  sha256sum "$(basename "$OUT_RUN")" > "$(basename "$OUT_RUN").sha256" 2>/dev/null \
    || shasum -a 256 "$(basename "$OUT_RUN")" > "$(basename "$OUT_RUN").sha256"
)

SIZE="$(du -h "$OUT_TGZ" | awk '{print $1}')"
RUN_SIZE="$(du -h "$OUT_RUN" | awk '{print $1}')"
echo
echo "Packaged successfully."
echo "  Archive   : $OUT_TGZ  ($SIZE)"
echo "  Installer : $OUT_RUN  ($RUN_SIZE)"
echo "  Checksums : ${OUT_TGZ}.sha256  ${OUT_RUN}.sha256"
echo
echo "Copy to server and install web UI:"
echo "  scp dist/$(basename "$OUT_RUN") user@server:"
echo "  ssh user@server 'chmod +x $(basename "$OUT_RUN") && sudo ./$(basename "$OUT_RUN") --web-service'"
echo
echo "Or classic tarball:"
echo "  scp dist/$(basename "$OUT_TGZ") user@server:"
echo "  ssh user@server 'tar xzf $(basename "$OUT_TGZ") && cd ${NAME} && sudo ./install.sh --web-service'"
