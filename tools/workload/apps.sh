#!/bin/bash
# Desktop-app sessions for the ACN measurement: each installed app is started
# from a flushed DNS cache, left to run, then quit - one capture per app.
#
#   sudo NETWORK=home tools/workload/apps.sh
#   sudo APPS="Slack Spotify" SECONDS_PER_APP=120 tools/workload/apps.sh
#
# A launch-and-idle session captures the app's own startup traffic: sign-in,
# sync, telemetry, update checks. It is reproducible; your normal use is not,
# so record that separately with tools/field.sh as a case study.
set -u
here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
# shellcheck source=../resolver.sh
. "$repo/tools/resolver.sh"
APPS="${APPS:-Slack Discord Spotify zoom.us Notion Cursor Microsoft\ Teams Figma WhatsApp Telegram Dropbox Microsoft\ Outlook Visual\ Studio\ Code}"
SECONDS_PER_APP="${SECONDS_PER_APP:-90}"
REPEAT="${REPEAT:-1}"
NETWORK="${NETWORK:-unlabelled}"
OUT="${OUT:-$repo/dist/runs}"

say() { printf '%s  %s\n' "$(date +%H:%M:%S)" "$*"; }
[ "$(uname)" = Darwin ] || { say "run on the Mac"; exit 1; }
[ "$(id -u)" = 0 ] && [ -n "${SUDO_USER:-}" ] || { say "run with sudo from your own account"; exit 1; }
user="$SUDO_USER"
uid="$(id -u "$user")"
as_user() { launchctl asuser "$uid" sudo -u "$user" "$@"; }
mkdir -p "$OUT"
chown "$user" "$OUT" 2>/dev/null || true
macos="$(sw_vers -productVersion)"
stamp="$(date +%Y%m%d-%H%M)"
caffeinate -dimsu -w $$ &

eval "set -- $APPS"
for name in "$@"; do
	app="/Applications/$name.app"
	[ -d "$app" ] || { say "skip $name: not installed"; continue; }
	if pgrep -fq "$app/Contents/MacOS/"; then
		as_user osascript -e "tell application \"$name\" to quit" >/dev/null 2>&1
		sleep 5
	fi
	ver="$(defaults read "$app/Contents/Info" CFBundleShortVersionString 2>/dev/null || echo unknown)"
	slug="$(printf '%s' "$name" | tr ' ' '_' )"
	base="$OUT/$stamp-$NETWORK-r$REPEAT-app-$slug"
	say "== $name $ver -> $(basename "$base").pcapng"
	resolver_probe # before the flush and the capture: its lookups are DNS traffic
	case "$RESOLVER_ENCRYPTED" in yes | likely)
		say "  WARNING: resolver $RESOLVER is likely encrypted; DNS answers will not be on the wire" ;;
	esac
	dscacheutil -flushcache; killall -HUP mDNSResponder 2>/dev/null; sleep 1
	started="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
	tcpdump -i pktap,all -s 2048 -U -w "$base.pcapng" >/dev/null 2>&1 &
	cap=$!
	sleep 2
	as_user open -a "$name"
	sleep "$SECONDS_PER_APP"
	as_user osascript -e "tell application \"$name\" to quit" >/dev/null 2>&1
	sleep 5
	kill -INT "$cap"; wait "$cap" 2>/dev/null
	cat >"$base.manifest.json" <<JSON
{
  "workload": "app-launch",
  "app": "$name",
  "app_version": "$ver",
  "cache": "cold",
  "repeat": $REPEAT,
  "network": "$NETWORK",
  "seconds": $SECONDS_PER_APP,
  "macos": "$macos",
$(resolver_manifest_fields)
  "started": "$started",
  "ended": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
JSON
	chown "$user" "$base.pcapng" "$base.manifest.json"
done
say "done. ./ohmyosi -report $OUT"
