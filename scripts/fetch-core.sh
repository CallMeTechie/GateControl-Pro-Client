#!/usr/bin/env bash
# Holt gatecontrol-client-core exakt auf dem in core.ref gepinnten Commit.
#
#   scripts/fetch-core.sh [--link] [ZIEL]
#
#   ZIEL    Zielverzeichnis (Standard: .core). Existiert es schon als
#           Git-Checkout (z.B. ../gatecontrol-client-core), wird dort nur der
#           gepinnte Commit geholt und ausgecheckt (detached HEAD).
#   --link  package.json-Abhängigkeit @gatecontrol/client-core auf file:ZIEL
#           umbiegen (nur für CI gedacht, die Änderung nicht committen).
#
# Optional: CORE_GIT_TOKEN (z.B. GITHUB_TOKEN) für authentifizierten Fetch.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO_URL="${CORE_REPO_URL:-https://github.com/CallMeTechie/gatecontrol-client-core.git}"

LINK=0
TARGET=".core"
for arg in "$@"; do
  case "$arg" in
    --link) LINK=1 ;;
    -h|--help) sed -n '2,13p' "$0"; exit 0 ;;
    *) TARGET="$arg" ;;
  esac
done

SHA="$(tr -d '[:space:]' < "$ROOT/core.ref")"
if ! [[ "$SHA" =~ ^[0-9a-f]{40}$ ]]; then
  echo "core.ref muss einen vollständigen 40-stelligen Commit-SHA enthalten (ist: '$SHA')" >&2
  exit 1
fi

cd "$ROOT"
AUTH=()
if [ -n "${CORE_GIT_TOKEN:-}" ]; then
  AUTH=(-c "http.https://github.com/.extraheader=AUTHORIZATION: basic $(printf 'x-access-token:%s' "$CORE_GIT_TOKEN" | base64 | tr -d '\n')")
fi

if [ -d "$TARGET/.git" ]; then
  if [ -n "$(git -C "$TARGET" status --porcelain --untracked-files=no)" ]; then
    echo "$TARGET hat uncommittete Änderungen – bitte erst sichern." >&2
    exit 1
  fi
else
  if [ -d "$TARGET" ] && [ -n "$(ls -A "$TARGET")" ]; then
    echo "$TARGET existiert, ist aber kein Git-Checkout – bitte prüfen/entfernen." >&2
    exit 1
  fi
  mkdir -p "$TARGET"
  git -C "$TARGET" init -q
fi

git -C "$TARGET" "${AUTH[@]}" fetch -q --depth 1 "$REPO_URL" "$SHA"
git -C "$TARGET" -c advice.detachedHead=false checkout -q FETCH_HEAD

HEAD_SHA="$(git -C "$TARGET" rev-parse HEAD)"
if [ "$HEAD_SHA" != "$SHA" ]; then
  echo "Checkout-Fehler: $TARGET steht auf $HEAD_SHA statt $SHA" >&2
  exit 1
fi
echo "gatecontrol-client-core @ $SHA -> $TARGET"

if [ "$LINK" = 1 ]; then
  CORE_DIR="$TARGET" node -e "const fs=require('fs');const p=require('./package.json');p.dependencies['@gatecontrol/client-core']='file:'+process.env.CORE_DIR;fs.writeFileSync('package.json',JSON.stringify(p,null,2)+'\n')"
fi
