#!/bin/bash
# Export what a real firewall displayed during one run, next to its capture.
#   export.sh <firewall> <capture-base> <begin "YYYY-MM-DD HH:MM:SS"> <end ...>
# Writes <capture-base>.<firewall>.csv, which `ohmyosi -eval` / `-report`
# pick up automatically as strategy real:<firewall>. Must run as root.
#
# littlesnitch: `littlesnitch log-traffic` (Little Snitch 6; needs Settings >
#   Security > "Allow access via Terminal").
#   https://help.obdev.at/littlesnitch6/cmd-log-traffic
# lulu: not automated yet - LuLu writes to the unified log
#   (subsystem com.objective-see.lulu); see tools/realtools/README.md.
set -u
fw="$1" base="$2" begin="$3" end="$4"
case "$fw" in
none | "") exit 0 ;;
littlesnitch)
	ls_cli="$(command -v littlesnitch || true)"
	[ -n "$ls_cli" ] || ls_cli="/Applications/Little Snitch.app/Contents/Components/littlesnitch"
	if [ ! -x "$ls_cli" ]; then
		echo "export: littlesnitch command not found; see tools/realtools/README.md" >&2
		exit 1
	fi
	"$ls_cli" log-traffic -b "$begin" -e "$end" >"$base.littlesnitch.csv" || {
		echo "export: log-traffic failed (is 'Allow access via Terminal' on?)" >&2
		exit 1
	}
	echo "export: $(($(wc -l <"$base.littlesnitch.csv") - 1)) Little Snitch rows -> $(basename "$base").littlesnitch.csv" >&2
	;;
lulu)
	log show --start "$begin" --end "$end" --level debug \
		--predicate 'subsystem == "com.objective-see.lulu"' --style ndjson >"$base.lulu.raw.ndjson" 2>/dev/null
	echo "export: raw LuLu log -> $(basename "$base").lulu.raw.ndjson (convert to $(basename "$base").lulu.csv; see README)" >&2
	;;
*)
	echo "export: unknown firewall $fw" >&2
	exit 1
	;;
esac
[ -n "${SUDO_USER:-}" ] && chown "$SUDO_USER" "$base".*.csv "$base".*.ndjson 2>/dev/null
exit 0
