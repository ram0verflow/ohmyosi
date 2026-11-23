#!/bin/bash
# Live challenge run: pktap capture + cmd/acn-challenge, with a manifest.
#
#   make challenge NETWORK=home                               # builds, then runs this with sudo
#   sudo NETWORK=home tools/realtools/challenge.sh            # all scenarios, 20 reps
#   sudo REPS=50 ONLY=crossprocess,cohost tools/realtools/challenge.sh
#   sudo FIREWALL=littlesnitch tools/realtools/challenge.sh   # label the run
#
# Writes dist/challenge/<stamp>-<network>-<firewall>.{pcapng,manifest.json,
# truth.json,log.jsonl}. Score it with:
#   ./ohmyosi -eval <capture>.pcapng -truth <capture>.truth.json
# FIREWALL only labels the run (none, littlesnitch, lulu): installing and
# configuring the firewall is a manual step (tools/realtools/README.md).
set -u
here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
cd "$repo" || exit 1
REPS="${REPS:-20}"
ONLY="${ONLY:-}"
NETWORK="${NETWORK:-unlabelled}"
FIREWALL="${FIREWALL:-none}"
LIST="${LIST:-V38GN}"
OUT="$repo/dist/challenge"

say() { printf '%s  %s\n' "$(date +%H:%M:%S)" "$*"; }
# shellcheck source=../resolver.sh
. "$repo/tools/resolver.sh"
[ "$(uname)" = Darwin ] || { say "run on the Mac"; exit 1; }
[ "$(id -u)" = 0 ] && [ -n "${SUDO_USER:-}" ] || { say "run with sudo from your own account (capture and DNS flush need root)"; exit 1; }
user="$SUDO_USER"
mkdir -p "$OUT" && chown "$user" "$OUT"

names="$OUT/tranco-$LIST-top1000.txt"
if [ ! -s "$names" ]; then
	say "fetching Tranco list $LIST, top 1000 (same list as the browsing workload)"
	curl -fsS "https://tranco-list.eu/download/$LIST/1000" | cut -d, -f2 | tr -d '\r' >"$names" || { say "download failed"; exit 1; }
	chown "$user" "$names"
fi

# Built beforehand as the user (make challenge does it): Go is usually not
# on root's PATH under sudo.
bin="$OUT/acn-challenge"
[ -x "$bin" ] || { say "build it first: go build -o dist/challenge/acn-challenge ./cmd/acn-challenge (or: make challenge)"; exit 1; }

# Probe before the capture: the probe's own lookups must not be in it.
resolver_probe
say "resolver $RESOLVER (ddr $RESOLVER_DDR, encrypted $RESOLVER_ENCRYPTED)"
case "$RESOLVER_ENCRYPTED" in yes | likely)
	say "WARNING: system DNS is likely encrypted; DNS answers will not be on the wire" ;;
esac

stamp="$(date +%Y%m%d-%H%M)"
base="$OUT/$stamp-$NETWORK-$FIREWALL"
started="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
begin_local="$(date '+%Y-%m-%d %H:%M:%S')"
say "capture -> $(basename "$base").pcapng"
tcpdump -i pktap,all -s 2048 -U -w "$base.pcapng" >/dev/null 2>&1 &
cap=$!
# Never leave a root tcpdump behind if the run dies part-way.
trap '[ -n "$cap" ] && kill -INT "$cap" 2>/dev/null' EXIT
sleep 2
caffeinate -dimsu -w $$ &

args=(-names "$names" -limit 1000 -n "$REPS" -o "$base")
[ -n "$ONLY" ] && args+=(-only "$ONLY")
"$bin" "${args[@]}"
rc=$?

sleep 2
kill -INT "$cap"; wait "$cap" 2>/dev/null; cap=
sleep 5 # let the firewall flush its interval statistics
"$here/export.sh" "$FIREWALL" "$base" "$begin_local" "$(date '+%Y-%m-%d %H:%M:%S')"
cat >"$base.manifest.json" <<JSON
{
  "workload": "challenge",
  "firewall": "$FIREWALL",
  "reps": $REPS,
  "only": "$ONLY",
  "network": "$NETWORK",
  "tranco_list": "$LIST",
$(resolver_manifest_fields)
  "macos": "$(sw_vers -productVersion)",
  "macos_build": "$(sw_vers -buildVersion)",
  "started": "$started",
  "ended": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
JSON
chown "$user" "$base".* 2>/dev/null
say "done (exit $rc). Score it:"
say "  ./ohmyosi -eval $base.pcapng -truth $base.truth.json"
