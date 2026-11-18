#!/usr/bin/env python3
"""
orbdata_plot.py - plot the CSV written by orbdata (one graph per variable).

  orbdata -e firmware.elf -w g_speed,d -w g_pwm -o data.csv -l 5000
  python3 orbdata_plot.py data.csv               # show
  python3 orbdata_plot.py data.csv -o plot.png   # save
  python3 orbdata_plot.py data.csv -x ticks      # target timestamps on the x axis

Live graph, scrolling while orbdata runs (like a logic analyser):

  orbdata -e firmware.elf -w g_speed,d -w g_pwm -L -o data.csv      # in one window
  python3 orbdata_plot.py data.csv --live                           # in another
  python3 orbdata_plot.py data.csv --live --window 30               # show the last 30 s

or in one line, without a file:

  orbdata -e firmware.elf -w g_speed,d -w g_pwm | python3 orbdata_plot.py - --live

Requires: pip install matplotlib
"""
import argparse
import csv
import sys
from collections import defaultdict

ap = argparse.ArgumentParser(description="Plot an orbdata CSV file")
ap.add_argument("csvfile", help="CSV file from orbdata -o, or - to read what orbdata prints (live only)")
ap.add_argument("-l", "--live", action="store_true", help="keep reading while orbdata writes, and scroll the graph")
ap.add_argument("-w", "--window", type=float, default=10.0, help="live: seconds of history shown (default 10)")
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



def parse(row):
    """One CSV row -> (variable, x, value), or None if it is not a sample"""
    try:
        name = row["variable"]
        v = float(int(row["value"], 16)) if row["value"].lower().startswith("0x") else float(row["value"])
        if a.xaxis == "ticks":
            x = float(row["ticks"])
        elif a.xaxis == "sample":
            x = None
        else:
            x = float(row["time_s"])
    except (KeyError, ValueError, TypeError, AttributeError):
        return None
    return name, x, v


if a.live:
    # ---- Live: a thread follows the file (or the pipe), the graph is redrawn a few times a second
    import threading
    import time
    from collections import deque
    import matplotlib.animation as animation

    MAXPOINTS = 200000
    FIELDS = ["time_s", "ticks", "variable", "value", "access", "pc"]
    data = {}                   # name -> (deque of x, deque of y)
    lock = threading.Lock()
    state = {"ended": False, "error": None}

    def lines():
        if a.csvfile == "-":
            for line in sys.stdin:
                yield line
            return
        while True:             # orbdata may not have made the file yet
            try:
                f = open(a.csvfile, "r", newline="")
                break
            except OSError:
                time.sleep(0.2)
        part = ""
        with f:
            while True:
                chunk = f.readline()
                if not chunk:
                    time.sleep(0.05)
                    continue
                part += chunk
                if part.endswith("\n"):          # only whole lines: orbdata may be half way through one
                    yield part
                    part = ""

    def reader():
        try:
            for line in lines():
                cells = line.strip().split(",")
                if len(cells) < 4 or cells[0] == "time_s":
                    continue
                s = parse(dict(zip(FIELDS, cells)))
                if not s:
                    continue
                name, x, v = s
                with lock:
                    if name not in data:
                        data[name] = (deque(maxlen=MAXPOINTS), deque(maxlen=MAXPOINTS), [0])
                    dx, dy, n = data[name]
                    n[0] += 1
                    dx.append(n[0] if x is None else x)
                    dy.append(v)
        except Exception as e:                    # noqa: keep the window alive and say why
            state["error"] = str(e)
        state["ended"] = True

    threading.Thread(target=reader, daemon=True).start()

    fig = plt.figure(figsize=(10, 5))
    plots = {}                  # name -> (axes, line)

    def layout():
        fig.clf()
        plots.clear()
        names = list(data)
        for i, name in enumerate(names):
            ax = fig.add_subplot(len(names), 1, i + 1, sharex=(plots[names[0]][0] if i else None))
            ln, = ax.step([], [], where="post", linewidth=1)
            ax.set_ylabel(name)
            ax.grid(True, alpha=0.3)
            plots[name] = (ax, ln)
        if names:
            plots[names[-1]][0].set_xlabel({"time": "host time (s)", "ticks": "target timestamp (ticks)", "sample": "sample"}[a.xaxis])
            fig.tight_layout()

    def update(_frame=None):
        with lock:
            snap = {n: (list(d[0]), list(d[1])) for n, d in data.items()}
        if not snap:
            fig.suptitle("waiting for samples from orbdata ...")
            return
        if set(snap) != set(plots):
            layout()
        fig.suptitle("")
        newest = max(x[-1] for x, _ in snap.values() if x)
        span = a.window if a.xaxis == "time" else None
        for name, (x, y) in snap.items():
            ax, ln = plots[name]
            if span:                               # keep one point before the window so the line enters from the left
                first = 0
                for i in range(len(x) - 1, -1, -1):
                    if x[i] < newest - span:
                        first = i
                        break
                x, y = x[first:], y[first:]
                x, y = x + [newest], y + [y[-1]]    # the value holds until the next change
            ln.set_data(x, y)
            lo, hi = min(y), max(y)
            pad = (hi - lo) * 0.08 or max(abs(hi) * 0.05, 1.0)
            ax.set_ylim(lo - pad, hi + pad)
            ax.set_title("%s = %g" % (name, y[-1]), fontsize=9, loc="right")
        ax0 = next(iter(plots.values()))[0]
        if span:
            ax0.set_xlim(max(newest - span, 0), max(newest, span))
        else:
            ax0.set_xlim(min(x[0] for x, _ in snap.values()), newest)

    if a.output:                                   # a picture of the last window, after orbdata has ended
        while not state["ended"]:
            time.sleep(0.1)
        update()
        fig.savefig(a.output, dpi=120)
        print("wrote", a.output)
    else:
        anim = animation.FuncAnimation(fig, update, interval=150, cache_frame_data=False)
        plt.show()
    sys.exit(state["error"] or 0)

if a.csvfile == "-":
    sys.exit("- (read from orbdata directly) needs --live")

xs, ys = defaultdict(list), defaultdict(list)
with open(a.csvfile, newline="") as f:
    for row in csv.DictReader(f):
        s = parse(row)
        if not s:
            continue
        name, x, v = s
        xs[name].append(len(xs[name]) if x is None else x)
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
