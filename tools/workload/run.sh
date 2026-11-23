#!/bin/bash
# Controlled browsing workload for the ACN measurement.
#
# For each browser x DoH setting it creates a fresh profile, flushes the system
# DNS cache, and visits the same fixed Tranco list twice while pktap captures:
#
#   cold  fresh profile, system DNS flushed: nothing cached anywhere.
#   warm  the browser is quit after the cold pass and relaunched with the SAME
#         profile, without flushing system DNS. System DNS and the browser's
#         disk cache are warm; its connection pool is fresh, so every
#         connection opens - and announces its name - inside the capture.
#
# Every capture gets a manifest recording browser and macOS versions, the
# system resolver, conditions and the Tranco list ID, so anyone can rerun the
# identical experiment.
#
#   sudo NETWORK=home tools/workload/run.sh            # all browsers, all conditions
#   sudo NETWORK=campus SITES=50 BROWSERS="chrome" tools/workload/run.sh
#   DRY_RUN=1 tools/workload/run.sh                    # print the plan, touch nothing
#
# Environment:
#   SITES     sites per pass (default 100; about 15 minutes per pass at DWELL=8)
#   DWELL     seconds on each site (default 8)
#   BROWSERS  any of: safari chrome firefox (default: all installed)
#   DOH       any of: off on (default: both; Safari only runs "off")
#   REPEAT    repetition number to record (run on different days: 1, 2, 3)
#   NETWORK   a label for the network you are on: home, campus, hotspot...
#   OUT       output directory (default dist/runs)
#
# Before running: quit Chrome and Firefox (fresh instances are launched with
# throwaway profiles), close other apps that use the network, and keep the Mac
# awake (caffeinate is used). Safari runs in your own profile - it has no
# throwaway-profile mode - so its "cold" pass only flushes system DNS, and the
# sites end up in your Safari history. The first run asks macOS to let
# Terminal control Safari/Chrome (Automation permission): allow it.
#
# Use a plain resolver (your router's). A public one such as 8.8.8.8 is
# upgraded to encrypted DNS by macOS and no answer reaches the capture; the
# manifest records the resolver and `ohmyosi -report` warns about it.
#
# The captures contain your own traffic: keep them, publish only the
# aggregate tables from `ohmyosi -report`.
set -u

here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
# shellcheck source=../resolver.sh
. "$repo/tools/resolver.sh"
SITES="${SITES:-100}"
DWELL="${DWELL:-8}"
DOH="${DOH:-off on}"
REPEAT="${REPEAT:-1}"
NETWORK="${NETWORK:-unlabelled}"
OUT="${OUT:-$repo/dist/runs}"
DRY_RUN="${DRY_RUN:-0}"

SAFARI=/Applications/Safari.app
CHROME="/Applications/Google Chrome.app"
FIREFOX=/Applications/Firefox.app

say() { printf '%s  %s\n' "$(date +%H:%M:%S)" "$*"; }
die() { say "error: $*"; exit 1; }

if [ "$DRY_RUN" != 1 ]; then
	[ "$(uname)" = Darwin ] || die "this drives macOS browsers and pktap; run it on the Mac"
	[ "$(id -u)" = 0 ] || die "run with sudo: pktap capture needs root"
	[ -n "${SUDO_USER:-}" ] || die "run via sudo from your own account, so browsers open as you"
fi
user="${SUDO_USER:-$(id -un)}"
uid="$(id -u "$user")"

# Browsers and AppleScript must run as the logged-in user, inside their GUI
# session - not as root.
as_user() {
	if [ "$DRY_RUN" = 1 ]; then echo "  [as $user] $*"; return 0; fi
	launchctl asuser "$uid" sudo -u "$user" "$@"
}

if [ -z "${BROWSERS:-}" ]; then
	BROWSERS=""
	[ -d "$SAFARI" ] && BROWSERS="$BROWSERS safari"
	[ -d "$CHROME" ] && BROWSERS="$BROWSERS chrome"
	[ -d "$FIREFOX" ] && BROWSERS="$BROWSERS firefox"
fi

version_of() { defaults read "$1/Contents/Info" CFBundleShortVersionString 2>/dev/null || echo unknown; }

# --- the site list: one fixed Tranco list, fetched once, reused by every run ---
list_dir="$repo/dist/workload"
mkdir -p "$list_dir" "$OUT"
# Created as root under sudo: hand them to the user, or they need sudo to manage captures.
[ "$DRY_RUN" = 1 ] || chown "$user" "$list_dir" "$OUT" 2>/dev/null || true
sites_file="$(ls "$list_dir"/tranco-*-top"$SITES".txt 2>/dev/null | head -1)"
if [ -z "$sites_file" ]; then
	say "fetching the latest Tranco list (fixed for all later runs)"
	meta="$(curl -fsS https://tranco-list.eu/api/lists/date/latest)" || die "could not reach tranco-list.eu"
	list_id="$(printf '%s' "$meta" | sed -n 's/.*"list_id": *"\([^"]*\)".*/\1/p')"
	[ -n "$list_id" ] || die "unexpected Tranco API reply: $meta"
	sites_file="$list_dir/tranco-$list_id-top$SITES.txt"
	curl -fsS "https://tranco-list.eu/download/$list_id/$SITES" | cut -d, -f2 | tr -d '\r' >"$sites_file" ||
		die "could not download list $list_id"
	chown "$user" "$sites_file" 2>/dev/null || true
fi
list_id="$(basename "$sites_file" | sed 's/^tranco-\(.*\)-top.*/\1/')"
n_sites="$(wc -l <"$sites_file" | tr -d ' ')"
say "list $list_id: $n_sites sites from $sites_file"

macos="$(sw_vers -productVersion 2>/dev/null || echo unknown)"
macos_build="$(sw_vers -buildVersion 2>/dev/null || echo unknown)"

# --- capture ---
cap_pid=""
start_capture() {
	if [ "$DRY_RUN" = 1 ]; then echo "  capture -> $1"; return 0; fi
	# snaplen covers pktap's own header (~156 bytes) too: 1600 cut full-size
	# IPv6 segments and with them the end of split ClientHellos.
	tcpdump -i pktap,all -s 2048 -U -w "$1" >/dev/null 2>&1 &
	cap_pid=$!
	sleep 2
}
stop_capture() {
	[ "$DRY_RUN" = 1 ] && return 0
	sleep 2
	kill -INT "$cap_pid" 2>/dev/null
	wait "$cap_pid" 2>/dev/null
	chown "$user" "$1" 2>/dev/null || true
}
flush_dns() {
	[ "$DRY_RUN" = 1 ] && { echo "  flush system DNS cache"; return 0; }
	dscacheutil -flushcache
	killall -HUP mDNSResponder 2>/dev/null || true
	sleep 1
}

manifest() { # file browser version doh cache pass started
	[ "$DRY_RUN" = 1 ] && return 0
	cat >"$1" <<EOF
{
  "workload": "tranco-browse",
  "browser": "$2",
  "browser_version": "$3",
  "doh": "$4",
  "cache": "$5",
  "pass": $6,
  "repeat": $REPEAT,
  "network": "$NETWORK",
  "tranco_list": "$list_id",
  "sites": $n_sites,
  "dwell_s": $DWELL,
  "macos": "$macos",
  "macos_build": "$macos_build",
$(resolver_manifest_fields)
  "started": "$7",
  "ended": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
EOF
	chown "$user" "$1" 2>/dev/null || true
}

# --- browser drivers ---
profile_root=""
# new_profile creates a throwaway profile and writes the DoH setting into it.
new_profile() { # browser doh
	if [ "$DRY_RUN" = 1 ]; then
		profile_root=/tmp/ohmyosi-profile.dry
		return 0
	fi
	profile_root="$(as_user mktemp -d /tmp/ohmyosi-profile.XXXXXX)" || die "could not create a browser profile"
	case "$1" in
	chrome)
		local mode=off
		[ "$2" = on ] && mode=secure
		# Chrome reads its DoH mode from Local State in the profile directory.
		as_user /bin/sh -c "printf '%s' '{\"dns_over_https\":{\"mode\":\"$mode\",\"templates\":\"https://cloudflare-dns.com/dns-query\"}}' > '$profile_root/Local State'"
		;;
	firefox)
		local trr=5
		[ "$2" = on ] && trr=3 # 3 = DoH only, no fallback; 5 = explicitly off
		as_user /bin/sh -c "cat > '$profile_root/user.js' <<EOF
user_pref(\"network.trr.mode\", $trr);
user_pref(\"network.trr.uri\", \"https://mozilla.cloudflare-dns.com/dns-query\");
user_pref(\"browser.shell.checkDefaultBrowser\", false);
user_pref(\"browser.aboutwelcome.enabled\", false);
user_pref(\"datareporting.policy.dataSubmissionEnabled\", false);
user_pref(\"browser.link.open_newwindow.override.external\", 1);
EOF"
		;;
	esac
}
# start_browser launches the browser on profile_root (Safari: your own profile).
start_browser() { # browser
	case "$1" in
	safari)
		as_user open -a Safari
		sleep 3
		as_user osascript -e 'tell application "Safari" to if (count of documents) = 0 then make new document'
		;;
	chrome)
		as_user open -na "Google Chrome" --args --user-data-dir="$profile_root" --no-first-run \
			--no-default-browser-check --disable-features=PrivacySandboxSettings4 about:blank
		sleep 5
		;;
	firefox)
		as_user "$FIREFOX/Contents/MacOS/firefox" -profile "$profile_root" about:blank >/dev/null 2>&1 &
		sleep 6
		;;
	esac
}
visit() { # browser url
	case "$1" in
	safari) as_user osascript -e "tell application \"Safari\" to set URL of front document to \"$2\"" >/dev/null 2>&1 ;;
	chrome) as_user osascript -e "tell application \"Google Chrome\" to set URL of active tab of front window to \"$2\"" >/dev/null 2>&1 ;;
	firefox) as_user "$FIREFOX/Contents/MacOS/firefox" -profile "$profile_root" "$2" >/dev/null 2>&1 ;;
	esac
}
# quit_browser quits and waits until the process is gone, so a relaunch on the
# same profile starts a new instance (fresh connection pool) and finds the
# profile unlocked. The profile is kept; drop_profile removes it.
quit_browser() { # browser
	local proc
	case "$1" in
	safari) proc=Safari; as_user osascript -e 'tell application "Safari" to quit' ;;
	chrome) proc="Google Chrome"; as_user osascript -e 'tell application "Google Chrome" to quit' ;;
	firefox) proc=firefox; as_user osascript -e 'tell application "Firefox" to quit' ;;
	esac
	[ "$DRY_RUN" = 1 ] && return 0
	local i
	for i in $(seq 1 30); do
		pgrep -x "$proc" >/dev/null || break
		sleep 1
	done
	pgrep -x "$proc" >/dev/null && die "$1 did not quit within 30 s"
	sleep 2
}
drop_profile() {
	[ "$DRY_RUN" = 1 ] || rm -rf "$profile_root"
}

browse_pass() { # browser visits-log
	local i=0
	while IFS= read -r site; do
		[ -n "$site" ] || continue
		i=$((i + 1))
		if [ "$DRY_RUN" = 1 ]; then
			[ "$i" -le 2 ] && echo "  visit https://$site/ (${DWELL}s)"
			continue
		fi
		# One line per visit (ms, lane, site) so the report can put each flow on
		# the page that caused it and give per-site rates.
		printf '%s000\tmain\t%s\n' "$(date +%s)" "$site" >>"$2"
		visit "$1" "https://$site/"
		sleep "$DWELL"
		[ $((i % 25)) = 0 ] && say "    $i/$n_sites"
	done <"$sites_file"
	[ "$DRY_RUN" = 1 ] && echo "  ... $n_sites sites"
}

# AppleScript and Firefox's remote control address "the running instance", so
# the user's own Chrome/Firefox must not be running alongside the test one.
if [ "$DRY_RUN" != 1 ]; then
	for b in $BROWSERS; do
		case "$b" in
		chrome) pgrep -x "Google Chrome" >/dev/null && die "quit Google Chrome first (a fresh instance is launched)" ;;
		firefox) pgrep -x firefox >/dev/null && die "quit Firefox first (a fresh instance is launched)" ;;
		esac
	done
fi

[ "$DRY_RUN" = 1 ] || caffeinate -dimsu -w $$ &

stamp="$(date +%Y%m%d-%H%M)"
for b in $BROWSERS; do
	case "$b" in
	safari) app="$SAFARI" ;;
	chrome) app="$CHROME" ;;
	firefox) app="$FIREFOX" ;;
	*) die "unknown browser $b" ;;
	esac
	[ -d "$app" ] || [ "$DRY_RUN" = 1 ] || { say "skip $b: not installed"; continue; }
	ver="$(version_of "$app")"
	for d in $DOH; do
		if [ "$b" = safari ] && [ "$d" = on ]; then
			say "skip safari doh=on: Safari has no per-browser DoH setting"
			continue
		fi
		say "== $b $ver, doh=$d, repeat $REPEAT, network $NETWORK"
		# Probe before flushing: the probe's own lookups must not be in the capture.
		if [ "$DRY_RUN" = 1 ]; then
			echo "  probe system resolver"
		else
			resolver_probe
			say "  resolver $RESOLVER (ddr $RESOLVER_DDR, encrypted $RESOLVER_ENCRYPTED)"
			case "$RESOLVER_ENCRYPTED" in yes | likely)
				say "  WARNING: system DNS is likely encrypted; DNS answers will not be on the wire" ;;
			esac
		fi
		new_profile "$b" "$d"
		for pass in 1 2; do
			cache=cold
			if [ "$pass" = 1 ]; then
				flush_dns
			else
				# Warm: same profile, system DNS left as the cold pass left it.
				cache=warm
				quit_browser "$b"
			fi
			start_browser "$b"
			base="$OUT/$stamp-$NETWORK-r$REPEAT-$b-doh$d-$cache"
			started="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
			say "  pass $pass ($cache) -> $(basename "$base").pcapng"
			start_capture "$base.pcapng"
			browse_pass "$b" "$base.visits.tsv"
			[ "$DRY_RUN" = 1 ] || chown "$user" "$base.visits.tsv" 2>/dev/null || true
			stop_capture "$base.pcapng"
			manifest "$base.manifest.json" "$b" "$ver" "$d" "$cache" "$pass" "$started"
		done
		quit_browser "$b"
		drop_profile
	done
done

say "done. Measure everything captured so far with:"
say "  ./ohmyosi -report $OUT"
