"""
orbtrace_gdb.py - show in gdb what the program did just before it stopped.

orbmortem keeps the latest instruction trace. Started with -j <file> it writes the source lines
of that trace to the file each time the trace stops, which is what happens when the debugger
halts the CPU. This script reads the file.

    orbmortem -e firmware.axf -j trace.journal          (in a terminal, left running)

    (gdb) source Support/orbtrace_gdb.py
    (gdb) trace-back              the last 20 source lines executed before the stop
    (gdb) trace-back 100          the last 100
    (gdb) trace-calls             the functions it went through, oldest first
    (gdb) trace-auto 10           show the last 10 lines at every stop (trace-auto off to end)
    (gdb) set orbtrace-journal D:/work/trace.journal    if the file is somewhere else
    (gdb) set orbtrace-flush off  do not push the end of the trace out at a stop (see below)

The end of the trace at a stop: a parallel trace port sends frames of 16 bytes and keeps an
unfinished one until more data arrive, so the last few bytes before a stop stay in the chip, and
a step over one source line may send nothing at all. At every stop this script therefore writes
one word each to ITM channels 29, 30 and 31 through the debugger; they fill the frame and the
waiting trace comes out. Nothing is done when the ITM is off. The words appear on those channels only.

Lines are printed as file:line, which VS Code turns into links. Needs a gdb built with Python.
"""
import linecache
import os
import time

import gdb


class _Journal(gdb.Parameter):
    """File written by orbmortem -j"""
    set_doc = "Set the file written by orbmortem -j"
    show_doc = "Show the file written by orbmortem -j"

    def __init__(self):
        super().__init__("orbtrace-journal", gdb.COMMAND_DATA, gdb.PARAM_FILENAME)
        self.value = "trace.journal"


class _Flush(gdb.Parameter):
    """Push the end of the trace out of the target at every stop"""
    set_doc = "Set whether the end of the trace is pushed out of the target at every stop"
    show_doc = "Show whether the end of the trace is pushed out of the target at every stop"

    def __init__(self):
        super().__init__("orbtrace-flush", gdb.COMMAND_DATA, gdb.PARAM_BOOLEAN)
        self.value = True


_journal = _Journal()
_flush = _Flush()

_ITM_STIM, _ITM_TER, _ITM_TCR, _ITM_LAR = 0xE0000000, 0xE0000E00, 0xE0000E80, 0xE0000FB0
_FLUSH_FIRST, _FLUSH_COUNT = 29, 3              # ITM channels 29..31: one word each, 15 bytes in all
_FLUSH_MASK = ((1 << _FLUSH_COUNT) - 1) << _FLUSH_FIRST


def _push_trace_out():
    """Complete the trace port's unfinished frame with ITM filler (see the top of this file).

    A frame holds 15 bytes and the unfinished one has at least one in it, so 15 bytes of filler
    always complete it. They go out as one write over three channels, and the channel enables are
    only looked at, not written, once they are set: two accesses to the target per stop, because
    each one costs a few milliseconds through a debug probe and stepping should stay quick.
    """
    try:
        inf = gdb.selected_inferior()

        def rd(addr):
            return int.from_bytes(bytes(inf.read_memory(addr, 4)), "little")

        def wr(addr, value):
            inf.write_memory(addr, value.to_bytes(4, "little"))

        ter = rd(_ITM_TER)
        if (ter & _FLUSH_MASK) != _FLUSH_MASK:
            # First stop after the firmware set the ITM up (it rewrites the enables)
            if not rd(_ITM_TCR) & 1:
                return                           # ITM off: trace is not set up, leave it alone
            wr(_ITM_LAR, 0xC5ACCE55)
            wr(_ITM_TER, ter | _FLUSH_MASK)
        inf.write_memory(_ITM_STIM + 4 * _FLUSH_FIRST, bytes(4 * _FLUSH_COUNT))
    except (gdb.error, RuntimeError):
        pass                                     # no target, or memory not reachable: not our business


_state = {"auto": 0, "stopped": 0.0}


def _read(wait):
    """Entries (file, line, function, text), oldest first, with repeats of one line folded"""
    path = os.path.expanduser(_journal.value)
    limit = time.time() + wait

    # orbmortem needs a moment after the halt to see that the trace has stopped and decode it
    while True:
        try:
            fresh = os.path.getmtime(path) >= _state["stopped"] - 0.2
        except OSError:
            fresh = False
        if fresh or time.time() >= limit:
            break
        time.sleep(0.1)

    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            rows = f.read().splitlines()
    except OSError:
        raise gdb.GdbError("No trace journal at %s.\nStart: orbmortem -e <elf> -j %s   "
                           "(or: set orbtrace-journal <file>)" % (path, path))

    out = []
    for row in rows:
        c = row.split("\t")
        if len(c) < 3 or not c[1].isdigit():
            continue
        e = (c[0].replace("\\", "/"), int(c[1]), c[2], c[3] if len(c) > 3 else "")
        if not out or out[-1][:2] != e[:2]:
            out.append(e)
    return out, fresh


def _text(e):
    return (e[3] or linecache.getline(e[0], e[1])).strip()


def _number(arg, default):
    arg = arg.strip()
    if not arg:
        return default
    try:
        n = int(arg, 0)
    except ValueError:
        raise gdb.GdbError("Give a number of lines")
    if n < 1:
        raise gdb.GdbError("Give a number of lines")
    return n


def _show(n, wait):
    entries, fresh = _read(wait)
    if not entries:
        gdb.write("The trace journal is empty: no trace has been captured yet.\n")
        return
    if not fresh:
        gdb.write("(trace is from an earlier stop: orbmortem has not written a new one)\n")
    last = entries[-n:]
    for i, e in enumerate(last):
        gdb.write("%4d  %s:%d  %s  %s\n" % (i - len(last) + 1, e[0], e[1], e[2], _text(e)))


class _TraceBack(gdb.Command):
    """trace-back [N]: the last N (default 20) source lines executed before the stop, oldest first.
The line numbered 0 is the last one traced."""

    def __init__(self):
        super().__init__("trace-back", gdb.COMMAND_DATA)

    def invoke(self, arg, from_tty):
        _show(_number(arg, 20), 2.0)


class _TraceCalls(gdb.Command):
    """trace-calls [N]: the last N (default 30) functions the program went through, oldest first."""

    def __init__(self):
        super().__init__("trace-calls", gdb.COMMAND_DATA)

    def invoke(self, arg, from_tty):
        entries, fresh = _read(2.0)
        runs = []
        for e in entries:
            if runs and runs[-1][0] == e[2]:
                runs[-1][3] += 1
            else:
                runs.append([e[2], e[0], e[1], 1])
        if not runs:
            gdb.write("The trace journal is empty: no trace has been captured yet.\n")
            return
        if not fresh:
            gdb.write("(trace is from an earlier stop: orbmortem has not written a new one)\n")
        last = runs[-_number(arg, 30):]
        for i, r in enumerate(last):
            gdb.write("%4d  %-28s %s:%d  (%d line%s)\n" % (i - len(last) + 1, r[0], r[1], r[2], r[3], "" if r[3] == 1 else "s"))


class _TraceAuto(gdb.Command):
    """trace-auto N|off: show the last N traced source lines every time the program stops."""

    def __init__(self):
        super().__init__("trace-auto", gdb.COMMAND_DATA)

    def invoke(self, arg, from_tty):
        _state["auto"] = 0 if arg.strip().lower() in ("off", "0", "") else _number(arg, 10)
        gdb.write("Trace at every stop: %s\n" % (("last %d lines" % _state["auto"]) if _state["auto"] else "off"))


def _on_stop(event):
    if _flush.value:
        _push_trace_out()
    _state["stopped"] = time.time()
    if _state["auto"]:
        try:
            _show(_state["auto"], 2.0)
        except gdb.GdbError as e:
            gdb.write("%s\n" % e)


_TraceBack()
_TraceCalls()
_TraceAuto()
gdb.events.stop.connect(_on_stop)
gdb.write("orbtrace: trace-back, trace-calls and trace-auto are available (journal: %s)\n" % _journal.value)
