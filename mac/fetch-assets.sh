#!/bin/bash
# Fetch bundled UI assets (MacBook Pro 3D model, hero fallback, etc.)
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
RES="$ROOT/Resources"
mkdir -p "$RES"

GLB="$RES/macbook-pro.glb"
USDZ="$RES/macbook-pro.usdz"
GLB_URL="https://raw.githubusercontent.com/AnubhavChaturvedi-GitHub/macbook-pro-threejs/main/MacBook%20Pro.glb"

if [[ ! -s "$GLB" ]]; then
  echo "→ downloading macbook-pro.glb (14\" M-series procedural model)…"
  curl -fsSL "$GLB_URL" -o "$GLB"
fi

if [[ ! -s "$USDZ" ]]; then
  echo "→ converting GLB → USDZ…"
  VENV="$ROOT/.asset-venv"
  if [[ ! -d "$VENV" ]]; then
    python3 -m venv "$VENV"
    "$VENV/bin/pip" install -q usd-core numpy
    if [[ ! -d "$ROOT/.usdzconvert" ]]; then
      git clone --depth 1 https://github.com/niw/usdzconvert.git "$ROOT/.usdzconvert"
    fi
    sed 's/usd-core==23.11/usd-core/' "$ROOT/.usdzconvert/requirements.txt" > /tmp/usdz-req.txt
    "$VENV/bin/pip" install -q -r /tmp/usdz-req.txt || true
  fi
  if "$VENV/bin/python3" "$ROOT/.usdzconvert/usdzconvert" "$GLB" "$USDZ" 2>/dev/null || \
     "$VENV/bin/python3" "$ROOT/.usdzconvert/usdzconvert" "$GLB" "$USDZ" 2>&1 | tail -1; then
    :
  fi
  if [[ ! -s "$USDZ" ]]; then
    echo "warning: USDZ conversion failed — run manually or commit macbook-pro.usdz" >&2
  fi
fi

if [[ ! -s "$RES/macbook-hero.png" ]]; then
  echo "→ downloading macbook-hero.png (fallback)…"
  curl -fsSL "https://pngimg.com/uploads/macbook/macbook_PNG48.png" -o "$RES/macbook-hero.png"
fi

echo "→ assets ready in $RES"
