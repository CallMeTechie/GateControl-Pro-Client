#!/usr/bin/env bash
# Setzt core.ref auf einen neuen gatecontrol-client-core-Commit.
#
#   scripts/bump-core.sh          -> aktueller Stand von core master
#   scripts/bump-core.sh <SHA>    -> genau dieser Commit (40 Zeichen)
#
# Danach: Änderung an core.ref per PR einreichen, CI testet gegen den neuen Stand.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO_URL="${CORE_REPO_URL:-https://github.com/CallMeTechie/gatecontrol-client-core.git}"

if [ $# -ge 1 ]; then
  SHA="$1"
else
  SHA="$(git ls-remote "$REPO_URL" refs/heads/master | cut -f1)"
fi

if ! [[ "$SHA" =~ ^[0-9a-f]{40}$ ]]; then
  echo "Kein gültiger 40-stelliger Commit-SHA: '$SHA'" >&2
  exit 1
fi

OLD="$(tr -d '[:space:]' < "$ROOT/core.ref" 2>/dev/null || true)"
echo "$SHA" > "$ROOT/core.ref"
echo "core.ref: ${OLD:-<leer>} -> $SHA"
