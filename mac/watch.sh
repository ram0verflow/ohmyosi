#!/usr/bin/env bash
# Rebuild and relaunch OhMyOSI whenever a source file changes.
#
# Start this once and leave it running. It closes the loop: sources change ->
# app rebuilds -> app relaunches, and the compiler output lands in
# dist/build.log where it can be read without anyone retyping a command.
set -u
cd "$(dirname "$0")/.."
mkdir -p dist

sig() {
  { find mac/Sources mac/Resources -type f \( -name '*.swift' -o -name '*.png' -o -name '*.usdz' \) \
      -exec stat -f "%m %N" {} + 2>/dev/null
    # The packaging script decides what lands in the bundle, so a change to it
    # has to rebuild too - the icon pipeline sat unused for a build because of this.
    stat -f "%m %N" mac/build-app.sh 2>/dev/null
  } | sort | shasum | cut -d' ' -f1
}

echo "watching mac/Sources — ctrl+c to stop"
prev=""
while true; do
  cur="$(sig)"
  if [ "$cur" != "$prev" ]; then
    prev="$cur"
    printf '%s  building… ' "$(date +%H:%M:%S)"
    if DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer \
       ./mac/build-app.sh > dist/build.log 2>&1; then
      echo "OK" >> dist/build.log
      pkill -f 'OhMyOSI.app/Contents/MacOS/OhMyOSI' 2>/dev/null || true
      sleep 0.4
      open dist/OhMyOSI.app
      echo "ok, relaunched"
    else
      echo "FAILED — see dist/build.log"
      tail -15 dist/build.log
    fi
  fi
  sleep 2
done
