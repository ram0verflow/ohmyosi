#!/usr/bin/env python3
# Figures for the report, plotted only from CSVs:
#   dist/runs.csv (make report), dist/analysis/challenge.csv (challenge_csv.py),
#   tools/analysis/baselines.csv (published figures, by hand)
# Run: <venv with matplotlib>/bin/python tools/analysis/figures.py
# Writes dist/analysis/fig_*.png and figures_numbers.csv (every plotted number,
# for checking against the CSVs).
import csv, math, os
from collections import defaultdict
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import Patch

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
OUT = os.path.join(ROOT, "dist/analysis")
os.makedirs(OUT, exist_ok=True)
# Reference categorical palette (light), fixed order.
C = ["#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#e87ba4", "#008300", "#6250d6", "#e34948"]
INK, INK2, GRID = "#0b0b0b", "#52514e", "#e4e3df"
plt.rcParams.update({
    "font.size": 9, "axes.edgecolor": INK2, "axes.labelcolor": INK, "xtick.color": INK2,
    "ytick.color": INK2, "axes.spines.top": False, "axes.spines.right": False,
    "axes.grid": True, "grid.color": GRID, "grid.linewidth": 0.6, "axes.axisbelow": True,
    "legend.frameon": False, "savefig.dpi": 200, "savefig.bbox": "tight",
})
numbers = []  # (figure, label, value, n)


def wilson(k, n, z=1.96):
    if n == 0:
        return (float("nan"),) * 3
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return 100 * p, 100 * (c - h), 100 * (c + h)


def save(fig, name):
    fig.savefig(os.path.join(OUT, name))
    plt.close(fig)


runs = list(csv.DictReader(open(os.path.join(ROOT, "dist/runs.csv"))))
browser = [r for r in runs if r["workload"] == "tranco-parallel"]

# (a) correlation error (last-answer, wrong + blind over readable) by browser x DoH
fig, ax = plt.subplots(figsize=(5.2, 3.0))
pool = defaultdict(lambda: [0, 0, 0])
for r in browser:
    p = pool[(r["subject"], r["doh"])]
    p[0] += int(r["wrong_last_answer"]) + int(r["blind_last_answer"])
    p[1] += int(r["readable"])
    p[2] += int(r["wrong_last_answer_no_coalesce"]) if r["wrong_last_answer_no_coalesce"] else 0
groups, w = ["off", "on"], 0.36
for i, subj in enumerate(["chrome", "firefox"]):
    for j, doh in enumerate(groups):
        k, n, _ = pool[(subj, doh)]
        p, lo, hi = wilson(k, n)
        x = j + (i - 0.5) * w
        ax.bar(x, p, w * 0.94, color=C[i], label=subj.capitalize() if j == 0 else None)
        ax.errorbar(x, p, yerr=[[p - lo], [hi - p]], color=INK, capsize=3, lw=1)
        ax.text(x, p + 2.5, f"{p:.1f}%", ha="center", color=INK, fontsize=8)
        numbers.append(("a", f"{subj} doh={doh} last-answer error", round(p, 1), n))
ax.set_xticks(range(2), ["DoH off", "DoH on"])
ax.set_ylim(0, 110)
ax.set_ylabel("flows named wrong or blank (%)")
ax.set_title("Last-answer correlation error, 2 runs pooled, 95% Wilson CI", loc="left", fontsize=9)
ax.legend(loc="upper left")
save(fig, "fig_a_error_by_browser_doh.png")

# (b) known-answer challenge: correct and misled per strategy, with and without Little Snitch
ch = list(csv.DictReader(open(os.path.join(OUT, "challenge.csv"))))
order = ["last-answer", "per-process", "littlesnitch-mac", "littlesnitch-mac-noverify",
         "header-first", "address-cache", "read-first", "real:littlesnitch"]
fig, ax = plt.subplots(figsize=(5.8, 3.4))
h = 0.38
for i, fw in enumerate(["none", "littlesnitch"]):
    rows = {r["strategy"]: r for r in ch if r["firewall"] == fw}
    for j, s in enumerate(order):
        if s not in rows:
            continue
        r = rows[s]
        y = j + (i - 0.5) * h
        v = float(r["correct_pct"])
        ax.barh(y, v, h * 0.94, color=C[i] if s != "real:littlesnitch" else C[7],
                label=("no firewall" if fw == "none" else "Little Snitch on") if j == 0 else None)
        ax.text(v + 1, y, f"{v:.1f}%  misled {r['misled']}", va="center", fontsize=7, color=INK)
        numbers.append(("b", f"{fw} {s} correct", v, int(r["flows"])))
        numbers.append(("b", f"{fw} {s} misled", int(r["misled"]), int(r["flows"])))
ax.set_yticks(range(len(order)), order)
ax.invert_yaxis()
ax.set_xlim(0, 135)
ax.set_xticks(range(0, 101, 25))
ax.set_xlabel("known-answer connections named correctly (%)")
ax.set_title("Challenge suite against ground truth (284 / 296 connections)", loc="left", fontsize=9)
ax.legend(handles=[Patch(color=C[0], label="no firewall"), Patch(color=C[1], label="Little Snitch on (models)"),
                   Patch(color=C[7], label="Little Snitch's own log")],
          ncol=3, loc="upper center", bbox_to_anchor=(0.4, -0.16), fontsize=7)
save(fig, "fig_b_challenge_truth.png")

# (c) causes of last-answer error, share per condition
causes = ["bypass", "coalesced", "cross-process", "stale", "co-hosted", "other-name"]
conds = [("chrome", "off"), ("firefox", "off"), ("chrome", "on"), ("firefox", "on")]
fig, ax = plt.subplots(figsize=(5.8, 2.6))
for i, (subj, doh) in enumerate(conds):
    tot = {c: sum(int(r[f"cause_{c}"]) for r in browser if (r["subject"], r["doh"]) == (subj, doh)) for c in causes}
    n = sum(tot.values())
    left = 0
    for k, c in enumerate(causes):
        v = 100 * tot[c] / n if n else 0
        ax.barh(i, v, 0.6, left=left, color=C[k], edgecolor="white", linewidth=1,
                label=c if i == 0 else None)
        if v >= 6:
            ax.text(left + v / 2, i, f"{v:.0f}%", ha="center", va="center", fontsize=7, color="white")
        left += v
        numbers.append(("c", f"{subj} doh={doh} cause {c} share", round(v, 1), n))
ax.set_yticks(range(4), [f"{s.capitalize()} DoH {d}\n(n={sum(int(r[f'cause_{c}']) for r in browser if (r['subject'], r['doh']) == (s, d) for c in causes)})" for s, d in conds])
ax.invert_yaxis()
ax.set_xlim(0, 100)
ax.set_xlabel("share of misnamed flows (%)")
ax.set_title("Why last-answer correlation gets the name wrong", loc="left", fontsize=9)
ax.legend(ncol=6, loc="upper center", bbox_to_anchor=(0.5, -0.32), fontsize=7, handlelength=1)
save(fig, "fig_c_causes.png")

# (d) per-app error for the app runs (apps with >= 5 readable flows)
apps = sorted((r for r in runs if r["workload"] == "app-launch" and int(r["readable"]) >= 5),
              key=lambda r: -int(r["readable"]))
fig, ax = plt.subplots(figsize=(5.2, 2.6))
for i, r in enumerate(apps):
    k = int(r["wrong_last_answer"]) + int(r["blind_last_answer"])
    n = int(r["readable"])
    p, lo, hi = wilson(k, n)
    ax.bar(i, p, 0.6, color=C[0])
    ax.errorbar(i, p, yerr=[[p - lo], [hi - p]], color=INK, capsize=3, lw=1)
    ax.text(i, hi + 3, f"{p:.0f}%\nn={n}", ha="center", fontsize=7, color=INK)
    numbers.append(("d", f"app {r['subject']} last-answer error", round(p, 1), n))
ax.set_xticks(range(len(apps)), [r["subject"].replace(" Browser", "") for r in apps])
ax.set_ylim(0, 115)
ax.set_ylabel("flows named wrong or blank (%)")
ax.set_title("Desktop apps, one 90 s run each (95% Wilson CI)", loc="left", fontsize=9)
save(fig, "fig_d_apps.png")

# (e) ours vs published baselines
bl = list(csv.DictReader(open(os.path.join(HERE, "baselines.csv"))))
fig, ax = plt.subplots(figsize=(5.8, 2.4))
for i, r in enumerate(bl):
    ax.barh(i - 0.18, float(r["theirs_pct"]), 0.34, color=C[2], label="published" if i == 0 else None)
    ax.barh(i + 0.18, float(r["ours_pct"]), 0.34, color=C[0], label="this study" if i == 0 else None)
    ax.text(float(r["theirs_pct"]) + 0.8, i - 0.18, f"{r['theirs_label']}", va="center", fontsize=7)
    ax.text(float(r["ours_pct"]) + 0.8, i + 0.18, f"{float(r['ours_pct']):.1f}%", va="center", fontsize=7)
    numbers.append(("e", f"{r['study']} theirs", float(r["theirs_pct"]), ""))
    numbers.append(("e", f"{r['study']} ours", float(r["ours_pct"]), ""))
ax.set_yticks(range(len(bl)), [f"{r['study']}\n{r['metric']}" for r in bl], fontsize=7)
ax.invert_yaxis()
ax.set_xlim(0, 60)
ax.set_xlabel("%  (units differ per study; see text)")
ax.legend(ncol=2, loc="upper center", bbox_to_anchor=(0.4, -0.3), fontsize=7)
save(fig, "fig_e_baselines.png")

with open(os.path.join(OUT, "figures_numbers.csv"), "w") as f:
    w = csv.writer(f)
    w.writerow(["figure", "label", "value", "n"])
    w.writerows(numbers)
print(f"wrote 5 figures and {len(numbers)} numbers to {OUT}")
