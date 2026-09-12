#!/bin/bash
# Measure observer cost separately from destination-identity accuracy.
# Run as root on macOS after building /tmp/ohmyosi and /tmp/identity-lab.
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "measure-overhead.sh: run as root (pktap and DNS port 53 require it)" >&2
  exit 1
fi

monitor_bin=${MONITOR_BIN:-/tmp/ohmyosi}
lab_bin=${LAB_BIN:-/tmp/identity-lab}
runs=${RUNS:-10}
seed=${SEED:-42}
port=${PORT:-17890}
snaplen=${SNAPLEN:-1600}
hold=${HOLD:-2s}
stamp=$(date +%Y%m%d-%H%M%S)
outdir=${OUTDIR:-/tmp/ohmyosi-overhead-${stamp}}
mkdir -p "${outdir}"

trace="${outdir}/trace.ndjson"
truth="${outdir}/truth.ndjson"
monitor_log="${outdir}/monitor.log"
lab_log="${outdir}/lab.log"
samples="${outdir}/process.tsv"
latency="${outdir}/api-latency.tsv"

[[ -x "${monitor_bin}" ]] || { echo "missing executable ${monitor_bin}" >&2; exit 1; }
[[ -x "${lab_bin}" ]] || { echo "missing executable ${lab_bin}" >&2; exit 1; }

printf 'at\tpcpu\trss_kb\n' >"${samples}"
printf 'at\ttime_s\tcode\n' >"${latency}"

cleanup() {
  if [[ -n "${monitor_pid:-}" ]]; then
    kill "${monitor_pid}" 2>/dev/null || true
    wait "${monitor_pid}" 2>/dev/null || true
  fi
}
trap cleanup EXIT INT TERM

"${monitor_bin}" -i pktap,all -addr "127.0.0.1:${port}" -no-rdns -no-icons \
  -asn=false -no-seed -interval 200ms -snaplen "${snaplen}" \
  -research-trace "${trace}" >"${monitor_log}" 2>&1 &
monitor_pid=$!

for _ in $(seq 1 100); do
  if curl -fsS "http://127.0.0.1:${port}/api/status" >/dev/null 2>&1; then
    break
  fi
  sleep 0.1
done

"${lab_bin}" -runs "${runs}" -seed "${seed}" -hold "${hold}" -out "${truth}" >"${lab_log}" 2>&1 &
lab_pid=$!
while kill -0 "${lab_pid}" 2>/dev/null; do
  now=$(date +%s.%N)
  ps -p "${monitor_pid}" -o %cpu=,rss= | awk -v now="${now}" '{printf "%s\t%s\t%s\n", now, $1, $2}' >>"${samples}" || true
  curl -sS -o /dev/null -w "${now}\t%{time_total}\t%{http_code}\n" \
    "http://127.0.0.1:${port}/api/status" >>"${latency}" || true
  sleep 0.2
done
wait "${lab_pid}"

sleep 0.5
kill "${monitor_pid}" 2>/dev/null || true
wait "${monitor_pid}" 2>/dev/null || true
monitor_pid=

trace_bytes=$(stat -f %z "${trace}")
sample_count=$(awk 'NR>1 {n++} END {print n+0}' "${samples}")
max_cpu=$(awk 'NR>1 && $2>m {m=$2} END {printf "%.2f", m+0}' "${samples}")
max_rss=$(awk 'NR>1 && $3>m {m=$3} END {printf "%d", m+0}' "${samples}")
avg_latency=$(awk 'NR>1 && $2!="" {sum+=$2; n++} END {if (n) printf "%.6f", sum/n; else print "0"}' "${latency}")

{
  printf 'monitor_pid=%s\n' "${monitor_pid:-stopped}"
  printf 'runs=%s seed=%s snaplen=%s hold=%s\n' "${runs}" "${seed}" "${snaplen}" "${hold}"
  printf 'trace_bytes=%s samples=%s max_cpu_percent=%s max_rss_kb=%s avg_api_latency_seconds=%s\n' \
    "${trace_bytes}" "${sample_count}" "${max_cpu}" "${max_rss}" "${avg_latency}"
  printf 'artifacts=%s\n' "${outdir}"
} | tee "${outdir}/summary.txt"
