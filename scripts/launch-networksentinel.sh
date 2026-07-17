#!/usr/bin/env bash
# Launch Network Sentinel with a sensible environment.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export PATH="${HOME}/.dotnet:${PATH}"
export DOTNET_ROOT="${DOTNET_ROOT:-${HOME}/.dotnet}"

# Prefer self-contained publish; fall back to framework-dependent / dotnet run
if [[ -x "$ROOT/bin/publish-sc/NetworkSentinel" ]]; then
  exec "$ROOT/bin/publish-sc/NetworkSentinel" "$@"
elif [[ -x "$ROOT/bin/publish/NetworkSentinel" ]]; then
  exec "$ROOT/bin/publish/NetworkSentinel" "$@"
elif [[ -x "$ROOT/bin/Release/net8.0/NetworkSentinel" ]]; then
  exec "$ROOT/bin/Release/net8.0/NetworkSentinel" "$@"
else
  cd "$ROOT"
  exec dotnet run -c Release --no-build "$@" 2>/dev/null || exec dotnet run -c Release "$@"
fi
