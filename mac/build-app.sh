#!/bin/bash
# Build OhMyOSI.app and optionally a .dmg
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
MAC="$ROOT/mac"
BUILD="$MAC/.build/release"
APP="$ROOT/dist/OhMyOSI.app"
DMG="$ROOT/dist/OhMyOSI.dmg"

export DEVELOPER_DIR="${DEVELOPER_DIR:-/Applications/Xcode.app/Contents/Developer}"
export SDKROOT="${SDKROOT:-$DEVELOPER_DIR/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk}"
export PATH="$DEVELOPER_DIR/usr/bin:$PATH"

if [[ ! -d "$DEVELOPER_DIR" ]]; then
  echo "Xcode is required. Install it from the App Store." >&2
  exit 1
fi

CURRENT="$(xcode-select -p 2>/dev/null || true)"
if [[ "$CURRENT" != "$DEVELOPER_DIR" ]]; then
  echo "note: xcode-select points at $CURRENT" >&2
  echo "      this build uses Xcode via DEVELOPER_DIR." >&2
  echo "      to fix permanently, run:" >&2
  echo "        sudo xcode-select -s $DEVELOPER_DIR" >&2
  echo >&2
fi

if ! "$DEVELOPER_DIR/usr/bin/xcodebuild" -version >/dev/null 2>&1; then
  echo "Xcode license not accepted yet. Run:" >&2
  echo "  sudo xcodebuild -license accept" >&2
  exit 1
fi

echo "→ compiling SwiftUI app (Xcode $( "$DEVELOPER_DIR/usr/bin/xcodebuild" -version | awk 'NR==1{print $2}' ))…"
"$MAC/fetch-assets.sh" 2>/dev/null || true
cd "$MAC"
swift build -c release 2>&1

BIN="$BUILD/OhMyOSI"
if [[ ! -f "$BIN" ]]; then
  echo "build failed: missing $BIN" >&2
  exit 1
fi

echo "→ packaging OhMyOSI.app…"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"

cat > "$APP/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleDevelopmentRegion</key>
  <string>en</string>
  <key>CFBundleExecutable</key>
  <string>OhMyOSI</string>
  <key>CFBundleIdentifier</key>
  <string>com.ram0verflow.ohmyosi</string>
  <key>CFBundleInfoDictionaryVersion</key>
  <string>6.0</string>
  <key>CFBundleName</key>
  <string>ohmyosi</string>
  <key>CFBundlePackageType</key>
  <string>APPL</string>
  <key>CFBundleShortVersionString</key>
  <string>0.2.0</string>
  <key>CFBundleVersion</key>
  <string>1</string>
  <key>LSMinimumSystemVersion</key>
  <string>14.0</string>
  <key>NSHighResolutionCapable</key>
  <true/>
  <key>CFBundleIconFile</key>
  <string>AppIcon</string>
  <key>NSPrincipalClass</key>
  <string>NSApplication</string>
</dict>
</plist>
PLIST

cp "$BIN" "$APP/Contents/MacOS/OhMyOSI"
chmod +x "$APP/Contents/MacOS/OhMyOSI"

if [[ -d "$MAC/Resources" ]]; then
  for asset in macbook-pro.usdz macbook-hero.png AppIcon.png; do
    [[ -f "$MAC/Resources/$asset" ]] && cp "$MAC/Resources/$asset" "$APP/Contents/Resources/"
  done
fi

# Build the .icns from the source PNG. macOS wants every size baked in; a
# single large PNG renders soft in the Dock and wrong in Finder's list view.
ICON_SRC="$MAC/Resources/AppIcon.png"
if [[ -f "$ICON_SRC" ]]; then
  ICONSET="$(mktemp -d)/AppIcon.iconset"
  mkdir -p "$ICONSET"
  for sz in 16 32 128 256 512; do
    sips -z $sz $sz "$ICON_SRC" --out "$ICONSET/icon_${sz}x${sz}.png" >/dev/null 2>&1
    sips -z $((sz*2)) $((sz*2)) "$ICON_SRC" --out "$ICONSET/icon_${sz}x${sz}@2x.png" >/dev/null 2>&1
  done
  if iconutil -c icns "$ICONSET" -o "$APP/Contents/Resources/AppIcon.icns" 2>/dev/null; then
    echo "→ icon built"
  fi
  rm -rf "$(dirname "$ICONSET")"
fi

# Ad-hoc sign so the Dock picks up the new icon instead of a cached one.
codesign --force --deep --sign - "$APP" >/dev/null 2>&1 || true
touch "$APP"

echo "→ built $APP"

if [[ "${1:-}" == "--dmg" ]]; then
  mkdir -p "$ROOT/dist"
  rm -f "$DMG"
  echo "→ creating disk image…"
  hdiutil create -volname "ohmyosi" -srcfolder "$APP" -ov -format UDZO "$DMG" >/dev/null
  echo "→ $DMG"
fi
