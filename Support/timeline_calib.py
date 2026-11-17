#!/usr/bin/env python3
"""
timeline_calib.py - turn the instruction (or cycle) counts in an orbprofile timeline into real time.

orbprofile -g writes a timeline whose time axis is the number of instructions executed. If one
function in it is known to run at a fixed rate (normally a timer interrupt such as SysTick_Handler)
it can be used as a ruler: the stretch between two of its calls is one period of real time. Each
stretch is scaled on its own, so parts of the program that execute fewer instructions per second
(more branches, slower memory) come out with their true length.

  python timeline_calib.py timeline.json -r SysTick_Handler -p 1ms
  python timeline_calib.py timeline.json -r TIM2_IRQHandler -p 10kHz -o real.json
  python timeline_calib.py timeline.json -p 1ms,10us       (firmware switches SysTick between 1 kHz and 100 kHz)

The reference function must be in the timeline: do not filter it out with orbprofile -G.
The result is as good as the reference: time is spread evenly over the instructions between two
reference calls, and time when the CPU sleeps is given to the instructions around it.
"""
import argparse
import bisect
import math
import re
import statistics
import sys

EVENT = re.compile(r'^(,?\s*\{"name":")((?:[^"\\]|\\.)*)(","ph":"X","ts":)(\d+(?:\.\d+)?)(,"dur":)(\d+(?:\.\d+)?)(.*)$', re.S)
NAMEARG = re.compile(r'^(.*"args":\{"name":")(.*)("\}\}\s*)$', re.S)
PROCESS = re.compile(r'\(time in (instructions|cycles)\)')


def period_us(text):
    """'1ms', '250us', '0.001s', '1kHz', '1000Hz' or a bare number of seconds -> microseconds"""
    m = re.fullmatch(r'\s*([0-9]*\.?[0-9]+(?:[eE][-+]?[0-9]+)?)\s*([a-zA-Zµ]*)\s*', text)
    if not m:
        raise argparse.ArgumentTypeError("period like 1ms, 250us, 0.001s or 1kHz")
    v, u = float(m.group(1)), m.group(2).lower().replace('µ', 'u')
    scale = {'': 1e6, 's': 1e6, 'ms': 1e3, 'us': 1.0, 'ns': 1e-3}
    freq = {'hz': 1.0, 'khz': 1e3, 'mhz': 1e6}
    if u in scale:
        us = v * scale[u]
    elif u in freq and v > 0:
        us = 1e6 / (v * freq[u])
    else:
        raise argparse.ArgumentTypeError("unit must be s, ms, us, ns, Hz, kHz or MHz")
    if us <= 0:
        raise argparse.ArgumentTypeError("period must be more than zero")
    return us


def period_list(text):
    return sorted(set(period_us(t) for t in text.split(',')), reverse=True)


ap = argparse.ArgumentParser(description="Scale an orbprofile timeline to real time using a function that runs at a known rate")
ap.add_argument("timeline", help="timeline file written by orbprofile -g")
ap.add_argument("-r", "--reference", default="SysTick_Handler", help="function that runs at a fixed rate (default SysTick_Handler)")
ap.add_argument("-p", "--period", type=period_list, default=period_list("1ms"),
                help="its period or rate: 1ms, 250us, 1kHz ... (default 1ms). If the firmware changes the rate while it "
                     "runs, give every rate used, e.g. 1ms,10us: each stretch gets the one that fits it")
ap.add_argument("-o", "--output", help="output file (default: <timeline>_calib.json)")
ap.add_argument("-k", "--keep-gaps", action="store_true",
                help="every stretch between two reference calls is exactly one period (default: a stretch much longer "
                     "than its neighbours is taken as several periods, i.e. missed reference calls)")
a = ap.parse_args()
out = a.output or re.sub(r'(\.json)?$', '_calib.json', a.timeline, count=1)

# ---- Pass 1: where the reference function starts ---------------------------------------------
ref = []
events = 0
with open(a.timeline, "r", encoding="utf-8", errors="replace") as f:
    for line in f:
        m = EVENT.match(line)
        if m:
            events += 1
            if m.group(2) == a.reference:
                ref.append(float(m.group(4)))

if not events:
    sys.exit("%s: no timeline events found (is it a file written by orbprofile -g?)" % a.timeline)
if len(ref) < 2:
    sys.exit("'%s' is in the timeline %d time(s); at least 2 are needed.\n"
             "Check the name, and that orbprofile -G did not filter it out." % (a.reference, len(ref)))

ref = sorted(set(ref))
gaps = [b - c for c, b in zip(ref, ref[1:])]

# ---- How many periods each stretch is --------------------------------------------------------
# The instruction rate changes with what the program does, so compare each stretch with the ones
# around it and not with the whole file.
missed = 0
span = []                                    # real time (us) of each stretch

if len(a.period) > 1:
    # Several rates. The longest stretches are the slowest rate; that gives the instruction rate of
    # the CPU, and every stretch then gets the period that brings it closest to that rate.
    top = sorted(gaps)[-max(1, len(gaps) // 100):]
    top = [g for g in top if g > top[-1] / 1.7]
    cpu = statistics.median(top) / a.period[0]           # counts per us
    for g in gaps:
        span.append(min(a.period, key=lambda p: abs(math.log(g / (p * cpu)))))
else:
    # One rate. The instruction rate changes with what the program does, so compare each stretch
    # with the ones around it and not with the whole file.
    for i, g in enumerate(gaps):
        n = 1
        if not a.keep_gaps:
            near = gaps[max(0, i - 8):i] + gaps[i + 1:i + 9]
            if near:
                ratio = g / statistics.median(near)
                if ratio > 1.7:
                    n = int(ratio + 0.5)
                    missed += n - 1
        span.append(n * a.period[0])

# Real time (us) at each reference call
real = [0.0]
for t in span:
    real.append(real[-1] + t)

rate0 = (real[1] - real[0]) / gaps[0]        # us per count before the first reference call
rateN = (real[-1] - real[-2]) / gaps[-1]     # and after the last one
lead = ref[0] * rate0                        # so that count 0 is time 0


def to_real(x):
    if x <= ref[0]:
        return lead - (ref[0] - x) * rate0
    if x >= ref[-1]:
        return lead + real[-1] + (x - ref[-1]) * rateN
    i = bisect.bisect_right(ref, x) - 1
    return lead + real[i] + (x - ref[i]) * (real[i + 1] - real[i]) / (ref[i + 1] - ref[i])


# ---- Pass 2: rewrite -------------------------------------------------------------------------
last = 0.0
unit = "counts"
with open(a.timeline, "r", encoding="utf-8", errors="replace") as f, open(out, "w", encoding="utf-8", newline="\n") as o:
    for line in f:
        m = EVENT.match(line)
        if m:
            ts, dur = float(m.group(4)), float(m.group(6))
            t0, t1 = to_real(ts), to_real(ts + dur)
            last = max(last, t1)
            o.write("%s%s%s%.3f%s%.3f%s" % (m.group(1), m.group(2), m.group(3), t0, m.group(5), max(t1 - t0, 0.001), m.group(7)))
        else:
            p = PROCESS.search(line)
            n = NAMEARG.search(line)
            if p and n and "\\" in n.group(2):
                # Older orbprofile wrote a Windows path here unescaped, which is not valid JSON: keep the file name
                line = n.group(1) + re.split(r'[\\/]', n.group(2))[-1] + n.group(3)
                p = PROCESS.search(line)
            if p:
                unit = p.group(1)
                line = line[:p.start()] + "(real time, from %s)" % a.reference.replace('\\', '\\\\').replace('"', '\\"') + line[p.end():]
            o.write(line)

# ---- Report ----------------------------------------------------------------------------------
rate = sorted(g / t for g, t in zip(gaps, span))          # counts per us = millions per second
print("%d events, %d calls of %s used as the reference" % (events, len(ref), a.reference))
for p in a.period:
    n = sum(1 for t in span if t == p)
    if len(a.period) > 1 or n:
        print("  period %g ms: %d stretches" % (p / 1e3, n))
print("Speed: %.1f to %.1f million %s per second (median %.1f)" % (rate[0], rate[-1], unit, statistics.median(rate)))
if rate[-1] > 3 * statistics.median(rate) or rate[0] < statistics.median(rate) / 3:
    print("WARNING: the speed varies a lot. The reference may not run at the rate(s) given all the time,\n"
          "or trace was lost; the result is not reliable where that happens.")
if missed:
    print("%d reference call(s) look missed (interrupts masked or trace lost); those stretches were taken as\n"
          "several periods. Use -k to treat every stretch as one period instead." % missed)
print("Timeline length: %.6f s" % (last / 1e6))
print("Written to %s" % out)
