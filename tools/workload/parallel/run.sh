#!/bin/bash
# Parallel browsing run: one pktap capture, many independent browser lanes.
#
#   sudo NETWORK=home REPEAT=1 DOH=off tools/workload/parallel/run.sh
#   sudo DOH=on LANES=chrome:4,firefox:2 SAFARI=1 SITES=500 tools/workload/parallel/run.sh
#
# One capture per DoH setting (DOH="off on" runs both, in that order; pass
# DOH="on off" on the next repeat to swap the order). Each capture gets
# <base>.manifest.json (with every lane's PIDs), <base>.visits.tsv and
# <base>.lanes.json. Then: make report.
#
# One-time setup: (cd tools/workload/parallel && npm ci). For a Safari lane:
# `sudo safaridriver --enable` once, and Safari > Develop > Allow Remote Automation.
set -u
here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/../../.." && pwd)"
LANES="${LANES:-chrome:4,firefox:2}"
SAFARI="${SAFARI:-0}"
DOH="${DOH:-off on}"
SITES="${SITES:-500}"
DWELL="${DWELL:-6}"
REPEAT="${REPEAT:-1}"
NETWORK="${NETWORK:-unlabelled}"
FIREWALL="${FIREWALL:-none}" # none | littlesnitch | lulu: exports its log next to each capture
LIST="${LIST:-V38GN}"
OUT="${OUT:-$repo/dist/runs}"

say() { printf '%s  %s\n' "$(date +%H:%M:%S)" "$*"; }
# shellcheck source=../../resolver.sh
. "$repo/tools/resolver.sh"
[ "$(uname)" = Darwin ] || { say "run on the Mac"; exit 1; }
[ "$(id -u)" = 0 ] && [ -n "${SUDO_USER:-}" ] || { say "run with sudo from your own account"; exit 1; }
user="$SUDO_USER"
uid="$(id -u "$user")"
as_user() { launchctl asuser "$uid" sudo -u "$user" "$@"; }
node="$(sudo -u "$user" -i which node 2>/dev/null)"
[ -n "$node" ] || { say "node not found for $user"; exit 1; }
[ -d "$here/node_modules/puppeteer-core" ] || { say "run once: (cd tools/workload/parallel && npm ci)"; exit 1; }

mkdir -p "$OUT" "$repo/dist/workload" && chown "$user" "$OUT" "$repo/dist/workload"
sites_file="$repo/dist/workload/tranco-$LIST-top$SITES.txt"
if [ ! -s "$sites_file" ]; then
	say "fetching Tranco $LIST top $SITES"
	curl -fsS "https://tranco-list.eu/download/$LIST/$SITES" | cut -d, -f2 | tr -d '\r' >"$sites_file" || { say "download failed"; exit 1; }
	chown "$user" "$sites_file"
fi

browsers="$(printf '%s' "$LANES" | tr ',' '\n' | cut -d: -f1 | sort -u | paste -sd, -)"
[ "$SAFARI" = 1 ] && browsers="$browsers,safari"
safari_flag=()
[ "$SAFARI" = 1 ] && safari_flag=(--safari)
protocol="$(sudo -u "$user" git -C "$repo" describe --tags --always --dirty 2>/dev/null || echo unknown)"
caffeinate -dimsu -w $$ &

stamp="$(date +%Y%m%d-%H%M)"
# Never leave a root tcpdump behind if the run dies part-way.
cap=
trap '[ -n "$cap" ] && kill -INT "$cap" 2>/dev/null' EXIT
for d in $DOH; do
	base="$OUT/$stamp-$NETWORK-r$REPEAT-parallel-doh$d-cold"
	say "== DoH $d: lanes $LANES, safari=$SAFARI -> $(basename "$base")"
	# Probe before flushing: the probe's own lookups must not be in the capture.
	resolver_probe
	say "   resolver $RESOLVER (ddr $RESOLVER_DDR, encrypted $RESOLVER_ENCRYPTED)"
	case "$RESOLVER_ENCRYPTED" in yes | likely)
		say "   WARNING: system DNS is likely encrypted; DNS answers will not be on the wire" ;;
	esac
	dscacheutil -flushcache; killall -HUP mDNSResponder 2>/dev/null; sleep 1
	started="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
	begin_local="$(date '+%Y-%m-%d %H:%M:%S')"
	tcpdump -i pktap,all -s 2048 -U -w "$base.pcapng" >/dev/null 2>&1 &
	cap=$!
	sleep 2
	as_user "$node" "$here/lanes.mjs" --sites "$sites_file" --browsers "$LANES" --doh "$d" \
		--dwell "$DWELL" --out "$base" ${safari_flag[@]+"${safari_flag[@]}"}
	sleep 3
	kill -INT "$cap"; wait "$cap" 2>/dev/null; cap=
	sleep 5
	"$repo/tools/realtools/export.sh" "$FIREWALL" "$base" "$begin_local" "$(date '+%Y-%m-%d %H:%M:%S')"
	ended="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
	# Merge the run's facts and the lanes (with their PIDs) into the manifest.
	as_user env BASE="$base" "$node" -e '
		const fs = require("fs"), b = process.env.BASE;
		const lanes = JSON.parse(fs.readFileSync(b + ".lanes.json", "utf8"));
		const m = JSON.parse(process.argv[1]);
		m.lanes = lanes;
		m.sites = lanes.reduce((n, l) => n + l.sites, 0);
		m.visits_ok = lanes.reduce((n, l) => n + l.ok, 0);
		m.visits_failed = lanes.reduce((n, l) => n + l.failed, 0);
		for (const l of lanes) m[l.browser + "_version"] = l.version;
		fs.writeFileSync(b + ".manifest.json", JSON.stringify(m, null, 2));
	' "{\"workload\":\"tranco-parallel\",\"browsers\":\"$browsers\",\"doh\":\"$d\",\"cache\":\"cold\",\"network\":\"$NETWORK\",\"repeat\":$REPEAT,\"firewall\":\"$FIREWALL\",\"tranco_list\":\"$LIST\",\"dwell_s\":$DWELL,\"lanes_spec\":\"$LANES\",\"resolver\":\"$RESOLVER\",\"resolver_ddr\":\"$RESOLVER_DDR\",\"resolver_encrypted\":\"$RESOLVER_ENCRYPTED\",\"protocol\":\"$protocol\",\"macos\":\"$(sw_vers -productVersion)\",\"macos_build\":\"$(sw_vers -buildVersion)\",\"started\":\"$started\",\"ended\":\"$ended\"}"
	chown "$user" "$base".* 2>/dev/null
done
say "done. make report"
