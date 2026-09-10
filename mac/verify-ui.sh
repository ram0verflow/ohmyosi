#!/bin/bash
# Build, open OhMyOSI, export PNG via in-app ImageRenderer snapshot.
# Usage: ./mac/verify-ui.sh [output.png]
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${1:-$ROOT/dist/ui-preview.png}"
export DEVELOPER_DIR="${DEVELOPER_DIR:-/Applications/Xcode.app/Contents/Developer}"

mkdir -p "$(dirname "$OUT")"
rm -f "$OUT"
"$ROOT/mac/build-app.sh"

if ! curl -sf http://127.0.0.1:7777/api/snapshot >/dev/null; then
  echo "warning: ohmyosi daemon not reachable on :7777 — graph will be empty" >&2
fi

osascript -e 'tell application "OhMyOSI" to quit' 2>/dev/null || true
sleep 0.4

open -n -a "$ROOT/dist/OhMyOSI.app" --args --verify --snapshot "$OUT"

for _ in $(seq 1 45); do
  if [[ -s "$OUT" ]]; then
    echo "screenshot → $OUT"
    file "$OUT"
    exit 0
  fi
  sleep 0.4
done

echo "error: snapshot not written within 18s" >&2
exit 1
