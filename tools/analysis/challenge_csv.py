#!/usr/bin/env python3
# Score each challenge capture against its truth file and tabulate the
# "AGAINST GROUND TRUTH" table into dist/analysis/challenge.csv.
# Run from the repo root after `make build`:
#   python3 tools/analysis/challenge_csv.py dist/challenge/20261123-2034-home-none ...
# (each argument is a capture base, without .pcapng)
import csv, json, os, re, subprocess, sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
OUT = os.path.join(ROOT, "dist/analysis")
os.makedirs(OUT, exist_ok=True)
ROW = re.compile(r"^\s+(\S+)\s+(\d+)\s+([\d.]+)%\s+(\d+)\s+(\d+)\s+(\d+)$", re.M)

w = csv.writer(open(os.path.join(OUT, "challenge.csv"), "w"))
w.writerow(["run", "firewall", "strategy", "flows", "correct_pct", "wrong", "missing", "misled"])
for base in sys.argv[1:]:
    run = os.path.basename(base)
    fw = json.load(open(base + ".manifest.json"))["firewall"]
    text = subprocess.run([os.path.join(ROOT, "ohmyosi"), "-eval", base + ".pcapng", "-truth", base + ".truth.json"],
                          capture_output=True, text=True, check=True).stdout
    open(os.path.join(OUT, f"challenge-{run}.txt"), "w").write(text)
    for m in ROW.finditer(text.split("AGAINST GROUND TRUTH")[1]):
        w.writerow([run, fw, *m.groups()])
    print(f"scored {run} ({fw})", file=sys.stderr)
