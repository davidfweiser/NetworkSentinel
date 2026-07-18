#!/usr/bin/env bash
# Build a portable, self-contained install tarball for Linux servers / desktops.
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

# Short README for operators
cat > "$STAGE/README-INSTALL.txt" <<EOF
Network Sentinel ${VERSION} (${RID})
====================================

Self-contained package — no .NET SDK/runtime required on the server.

Quick install (system-wide, needs sudo):
  tar xzf ${NAME}.tar.gz
  cd ${NAME}
  sudo ./install.sh

User install (no root):
  ./install.sh --user

Run after install:
  networksentinel --tui          # terminal UI (recommended on servers)
  networksentinel                # GUI if display present; else auto-TUI
  networksentinel --help

Uninstall:
  sudo networksentinel-uninstall
  # or:  sudo ./uninstall.sh
  # user install:  ./uninstall.sh --user

Firewall notes:
  - Do not run the whole app as root on a desktop (Wayland).
  - Blocking IPs uses pkexec/sudo for nft/iptables only.
  - On a headless server, install policykit-1 or use sudo so elevation works.

Data / settings:
  ~/.local/share/NetworkSentinel/
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

SIZE="$(du -h "$OUT_TGZ" | awk '{print $1}')"
echo
echo "Packaged successfully."
echo "  Archive : $OUT_TGZ  ($SIZE)"
echo "  Checksum: ${OUT_TGZ}.sha256"
echo
echo "Copy to server and install:"
echo "  scp dist/$(basename "$OUT_TGZ") user@server:"
echo "  ssh user@server 'tar xzf $(basename "$OUT_TGZ") && cd ${NAME} && sudo ./install.sh'"
echo "  ssh user@server 'networksentinel --tui'"
