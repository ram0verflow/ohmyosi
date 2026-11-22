#!/bin/sh
# Field capture for the ACN measurement. Captures every interface through
# pktap, flushes the DNS cache so lookups appear on the wire, and runs the
# read-vs-inferred report when you stop it with Ctrl-C.
#
# The capture holds your own traffic. Keep it private; publish the tables.
set -e
[ "$(id -u)" = 0 ] || { echo "run with sudo: pktap needs root"; exit 1; }
out="${1:-dist/field-$(date +%Y%m%d-%H%M).pcapng}"
mkdir -p "$(dirname "$out")"
# A field manifest has no "workload" key, so the report still treats the run
# as a field capture; it records the system resolver (see tools/resolver.sh).
. "$(dirname "$0")/resolver.sh"
resolver_probe
case "$RESOLVER_ENCRYPTED" in yes | likely)
	echo "WARNING: resolver $RESOLVER is likely encrypted; DNS answers will not be on the wire" ;;
esac
cat >"${out%.pcapng}.manifest.json" <<JSON
{
$(resolver_manifest_fields)
  "macos": "$(sw_vers -productVersion 2>/dev/null || echo unknown)",
  "macos_build": "$(sw_vers -buildVersion 2>/dev/null || echo unknown)",
  "started": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
JSON
chown "${SUDO_USER:-root}" "${out%.pcapng}.manifest.json" 2>/dev/null || true
echo "capturing to $out"
echo "now: quit and reopen your browser and apps, then use the machine normally."
echo "Ctrl-C when done (20 minutes is plenty)."
tcpdump -i pktap,all -s 2048 -U -w "$out" 2>/dev/null &
pid=$!
sleep 1
killall -HUP mDNSResponder 2>/dev/null || true
trap 'kill $pid 2>/dev/null; wait $pid 2>/dev/null; echo; ./ohmyosi -eval "$out"; ./ohmyosi -eval "$out" -eval-json > "${out%.pcapng}.json"; chown "${SUDO_USER:-root}" "$out" "${out%.pcapng}.json" 2>/dev/null; echo "json: ${out%.pcapng}.json"' INT TERM
wait $pid
