#!/usr/bin/env python3
# Draw 50 random "wrong name" flows (last-answer shows a name that differs from
# the handshake name) from the parallel browsing runs, for hand-checking in
# Wireshark. Usage: handcheck_sample.py <eval-json>... > handcheck.csv
import csv, json, random, sys, os

rows = []
for path in sys.argv[1:]:
    run = os.path.basename(path).removesuffix(".json")
    for r in json.load(open(path))["results"]:
        v = r.get("verdicts", {}).get("last-answer", {})
        hs, pick = v.get("handshake"), v.get("dns_pick")
        # ech-outer flows show the ECH front, are excluded from grading, so not sampled.
        if not hs or not pick or hs == pick or v.get("class") == "ech-outer":
            continue
        proto, ends = r["key"].split(" ")
        local, remote = ends.split(">")
        lport = local.rsplit(":", 1)[1]
        rip, rport = remote.rsplit(":", 1)
        rip = rip.strip("[]")
        ipf = "ipv6" if ":" in rip else "ip"
        rows.append({
            "run": run, "opened": r["opened"], "process": r["comm"], "pid": r["pid"],
            "proto": proto, "remote": remote, "handshake_name": hs, "shown_name": pick,
            "tool_class": v.get("class"), "tool_cause": v.get("cause", ""),
            "coalesce_candidates": " ".join(v.get("coalesce", [])),
            "flow_filter": f"{ipf}.addr=={rip} && {proto}.port=={lport}",
            "dns_filter": f"dns.{'aaaa' if ipf == 'ipv6' else 'a'}=={rip}",
            "label": "", "notes": "",
        })

random.seed(20261123)
sample = random.sample(rows, min(50, len(rows)))
sample.sort(key=lambda x: (x["run"], x["opened"]))
w = csv.DictWriter(sys.stdout, fieldnames=list(sample[0].keys()))
w.writeheader()
w.writerows(sample)
print(f"{len(rows)} wrong-name flows, sampled {len(sample)}", file=sys.stderr)
