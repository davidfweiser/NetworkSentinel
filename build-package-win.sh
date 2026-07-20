#!/usr/bin/env bash
set -euo pipefail
export PATH="/c/Program Files/dotnet:${HOME}/.dotnet:${PATH}"
export DOTNET_ROOT="${DOTNET_ROOT:-/c/Program Files/dotnet}"
export LC_ALL=C.UTF-8
export LANG=C.UTF-8
cd "$(dirname "$0")"
echo "dotnet: $(command -v dotnet || true)"
dotnet --version
exec bash ./scripts/package.sh linux-x64
