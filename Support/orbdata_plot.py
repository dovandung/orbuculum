#!/usr/bin/env python3
"""
orbdata_plot.py - plot the CSV written by orbdata (one graph per variable).

  orbdata -e firmware.elf -w g_speed,d -w g_pwm -o data.csv -l 5000
  python3 orbdata_plot.py data.csv               # show
  python3 orbdata_plot.py data.csv -o plot.png   # save
  python3 orbdata_plot.py data.csv -x ticks      # target timestamps on the x axis

Requires: pip install matplotlib
"""
import argparse
import csv
import sys
from collections import defaultdict

ap = argparse.ArgumentParser(description="Plot an orbdata CSV file")
ap.add_argument("csvfile")
ap.add_argument("-o", "--output", help="write the plot to this file instead of showing it")
ap.add_argument("-x", "--xaxis", choices=["time", "ticks", "sample"], default="time",
                help="x axis: host time in s (default), target timestamp ticks, or sample number")
a = ap.parse_args()

try:
    import matplotlib
    if a.output:
        matplotlib.use("Agg")
    import matplotlib.pyplot as plt
except ImportError:
    sys.exit("matplotlib is required:  pip install matplotlib")

xs, ys = defaultdict(list), defaultdict(list)
with open(a.csvfile, newline="") as f:
    for row in csv.DictReader(f):
        name = row["variable"]
        try:
            v = float(int(row["value"], 16)) if row["value"].lower().startswith("0x") else float(row["value"])
        except ValueError:
            continue
        if a.xaxis == "ticks":
            if not row["ticks"]:
                continue
            x = float(row["ticks"])
        elif a.xaxis == "sample":
            x = len(xs[name])
        else:
            x = float(row["time_s"])
        xs[name].append(x)
        ys[name].append(v)

if not xs:
    sys.exit("no samples in " + a.csvfile)

fig, axes = plt.subplots(len(xs), 1, sharex=(a.xaxis != "sample"), figsize=(10, 2.4 * len(xs) + 0.6), squeeze=False)
for ax, name in zip(axes[:, 0], xs):
    ax.step(xs[name], ys[name], where="post", linewidth=1)
    ax.set_ylabel(name)
    ax.grid(True, alpha=0.3)
axes[-1, 0].set_xlabel({"time": "host time (s)", "ticks": "target timestamp (ticks)", "sample": "sample"}[a.xaxis])
fig.tight_layout()
if a.output:
    fig.savefig(a.output, dpi=120)
    print("wrote", a.output)
else:
    plt.show()
