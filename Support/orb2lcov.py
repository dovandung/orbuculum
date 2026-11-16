#!/usr/bin/env python3
"""
orb2lcov.py - Convert orbprofile (Orbuculum) callgrind output into an lcov
.info coverage file, so genhtml / VS Code Coverage Gutters can show which
source lines ran (green) and which never ran (red).

  orbprofile -e firmware.elf -I 10000 -z profile.out
  python3 orb2lcov.py -e firmware.elf -i Src/ -o coverage.info profile.out
  genhtml --branch-coverage coverage.info -o report

How it works
  1. Parse the callgrind file written by orbprofile: every executed
     instruction address and how many times it ran (event "Inst").
  2. Read the DWARF line table from the ELF. That lists EVERY executable
     source line, so lines that never ran are reported with 0 hits
     (orbprofile only writes addresses that were executed).
  3. Line hits  = highest execution count of any instruction on that line.
     Function hits = execution count of the function's first instruction.
  4. Branch coverage comes from the 'jcnd=' lines orbprofile writes for every
     conditional jump (B<c>, CBZ, CBNZ) that executed: branch 0 = jumped,
     branch 1 = fell through. Use 'genhtml --branch-coverage' to show it.
  5. Several profile files can be given; their counts are added together
     (e.g. coverage of test run 1 + test run 2).

Requires: pip install pyelftools
"""

import argparse
import bisect
import os
import sys
from collections import defaultdict

try:
    from elftools.elf.elffile import ELFFile
except ImportError:
    sys.exit("pyelftools is required:  pip install pyelftools")


# --------------------------------------------------------------------------
# 1. callgrind (orbprofile) parser
# --------------------------------------------------------------------------
def _pos(token, prev):
    """Decode one callgrind position field ('*', '+n', '-n' or absolute)."""
    if token == "*":
        return prev
    if token[0] in "+-":
        return prev + int(token, 10)
    return int(token, 0)


def parse_callgrind(path, counts, branches):
    """Add {address: instruction_count} and {address: [taken, executed]} for
    conditional jumps from one orbprofile file into counts / branches."""
    positions = ["line"]
    events = None
    prev = None
    n_lines = 0
    jcnd = None          # (taken, executed) waiting for its source position line

    with open(path, "r", errors="replace") as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith("#"):
                # orbprofile writes '## --- Calls Follow ---' before the
                # call-graph section; call costs must not count as executions
                if line.startswith("## ") and "Calls" in line:
                    break
                continue
            if line.startswith("positions:"):
                positions = line.split(":", 1)[1].split()
                continue
            if line.startswith("events:"):
                events = line.split(":", 1)[1].split()
                continue
            if line.startswith(("calls=", "cfl=", "cfi=", "cfn=", "cob=")):
                break  # start of call section
            if line.startswith("jcnd="):
                # KCacheGrind form: jcnd=<taken>/<executed> <target position>
                tk, ex = line[5:].split()[0].split("/")
                jcnd = (int(tk), int(ex))
                continue
            if line.startswith("jump="):
                jcnd = None
                continue
            if "=" in line.split()[0] or ":" in line.split()[0]:
                continue  # fl=, fn=, ob=, creator:, summary:, event: ...

            parts = line.split()
            npos = len(positions)
            if len(parts) < npos:
                continue
            if prev is None:
                prev = [0] * npos
            cur = [_pos(parts[i], prev[i]) for i in range(npos)]
            prev = cur

            addr = cur[positions.index("instr")] if "instr" in positions else None
            if addr is None:
                sys.exit(f"{path}: no 'instr' position - not an orbprofile file?")

            if jcnd is not None:
                # the line after jcnd= is the jump's own (source) position
                b = branches.setdefault(addr, [0, 0])
                b[0] += jcnd[0]
                b[1] += jcnd[1]
                jcnd = None
                if len(parts) == npos:
                    continue
            if len(parts) < npos + 1:
                continue
            inst = int(parts[npos])  # first event = Inst
            counts[addr] += inst
            n_lines += 1

    if events and events[0] != "Inst":
        print(f"warning: {path}: first event is {events[0]}, expected Inst",
              file=sys.stderr)
    return n_lines


# --------------------------------------------------------------------------
# 2. ELF / DWARF
# --------------------------------------------------------------------------
def _decode(x):
    return x.decode("utf-8", "replace") if isinstance(x, bytes) else x


def _cu_file_table(cu, lineprog):
    """Return a function: line-table file index -> absolute source path."""
    top = cu.get_top_DIE()
    comp_dir = _decode(top.attributes["DW_AT_comp_dir"].value) \
        if "DW_AT_comp_dir" in top.attributes else ""
    ver = lineprog.header["version"]
    dirs = [_decode(d) for d in lineprog.header["include_directory"]]
    files = lineprog.header["file_entry"]

    def path_of(index):
        if ver >= 5:
            fe = files[index]
            d = dirs[fe.dir_index] if fe.dir_index < len(dirs) else ""
        else:
            if index == 0 or index > len(files):
                return None
            fe = files[index - 1]
            d = comp_dir if fe.dir_index == 0 else dirs[fe.dir_index - 1]
        name = _decode(fe.name)
        p = name if os.path.isabs(name) else os.path.join(d, name)
        if not os.path.isabs(p) and comp_dir:
            p = os.path.join(comp_dir, p)
        return os.path.normpath(p)

    return path_of


def read_elf(elf_path):
    """
    Returns
      ranges : list of (start, end, file, line), sorted by start
      funcs  : list of (name, low_pc, file, line)
    """
    ranges = []
    funcs = []
    with open(elf_path, "rb") as fh:
        elf = ELFFile(fh)
        if not elf.has_dwarf_info():
            sys.exit(f"{elf_path} has no debug info - build with -g")
        dwarf = elf.get_dwarf_info()

        for cu in dwarf.iter_CUs():
            lp = dwarf.line_program_for_CU(cu)
            if lp is None:
                continue
            path_of = _cu_file_table(cu, lp)
            cache = {}

            prev = None
            for entry in lp.get_entries():
                st = entry.state
                if st is None:
                    continue
                if prev is not None and st.address > prev.address and prev.line:
                    fi = prev.file
                    if fi not in cache:
                        cache[fi] = path_of(fi)
                    if cache[fi]:
                        ranges.append((prev.address, st.address, cache[fi], prev.line))
                prev = None if st.end_sequence else st

            # functions with code (skip declarations / abstract inline copies)
            for die in cu.iter_DIEs():
                if die.tag != "DW_TAG_subprogram":
                    continue
                if "DW_AT_low_pc" not in die.attributes:
                    continue
                name_die = die
                if "DW_AT_name" not in die.attributes:
                    for ref in ("DW_AT_specification", "DW_AT_abstract_origin"):
                        if ref in die.attributes:
                            name_die = die.get_DIE_from_attribute(ref)
                            break
                if "DW_AT_name" not in name_die.attributes:
                    continue
                low = die.attributes["DW_AT_low_pc"].value
                funcs.append((_decode(name_die.attributes["DW_AT_name"].value), low))

    ranges.sort()
    return ranges, funcs


# --------------------------------------------------------------------------
# 3. build coverage
# --------------------------------------------------------------------------
def build(ranges, funcs, counts, branches, keep):
    addrs = sorted(counts)
    lines = defaultdict(dict)          # file -> {line: hits}
    starts = [r[0] for r in ranges]

    for start, end, path, line in ranges:
        if not keep(path):
            continue
        i = bisect.bisect_left(addrs, start)
        hits = 0
        while i < len(addrs) and addrs[i] < end:
            hits = max(hits, counts[addrs[i]])
            i += 1
        d = lines[path]
        d[line] = max(d.get(line, 0), hits)

    fns = defaultdict(dict)            # file -> {name: (line, hits)}
    for name, low in funcs:
        j = bisect.bisect_right(starts, low) - 1
        if j < 0 or not (ranges[j][0] <= low < ranges[j][1]):
            continue
        path, line = ranges[j][2], ranges[j][3]
        if not keep(path):
            continue
        hits = counts.get(low, 0)
        old = fns[path].get(name)
        if old is None or hits > old[1]:
            fns[path][name] = (line, hits)

    brs = defaultdict(lambda: defaultdict(list))   # file -> line -> [(taken, executed)]
    for addr in sorted(branches):
        j = bisect.bisect_right(starts, addr) - 1
        if j < 0 or not (ranges[j][0] <= addr < ranges[j][1]):
            continue
        path, line = ranges[j][2], ranges[j][3]
        if keep(path):
            brs[path][line].append(tuple(branches[addr]))
    return lines, fns, brs


def write_lcov(out, lines, fns, brs, test_name, strip):
    def show(p):
        if strip and p.startswith(strip):
            p = p[len(strip):].lstrip("/\\")
        return p

    tot_l = hit_l = tot_f = hit_f = tot_b = hit_b = 0
    with open(out, "w") as o:
        for path in sorted(lines):
            o.write(f"TN:{test_name}\nSF:{show(path)}\n")
            for name, (ln, h) in sorted(fns.get(path, {}).items(), key=lambda x: x[1][0]):
                o.write(f"FN:{ln},{name}\n")
            for name, (ln, h) in sorted(fns.get(path, {}).items(), key=lambda x: x[1][0]):
                o.write(f"FNDA:{h},{name}\n")
            f = fns.get(path, {})
            o.write(f"FNF:{len(f)}\nFNH:{sum(1 for v in f.values() if v[1])}\n")
            nb = hb = 0
            for ln in sorted(brs.get(path, {})):
                for blk, (taken, executed) in enumerate(brs[path][ln]):
                    for br, cnt in ((0, taken), (1, executed - taken)):
                        o.write(f"BRDA:{ln},{blk},{br},{cnt if executed else '-'}\n")
                        nb += 1
                        hb += 1 if cnt else 0
            if nb:
                o.write(f"BRF:{nb}\nBRH:{hb}\n")
            tot_b += nb; hit_b += hb
            for ln in sorted(lines[path]):
                o.write(f"DA:{ln},{lines[path][ln]}\n")
            lf = len(lines[path])
            lh = sum(1 for v in lines[path].values() if v)
            o.write(f"LF:{lf}\nLH:{lh}\nend_of_record\n")
            tot_l += lf; hit_l += lh
            tot_f += len(f); hit_f += sum(1 for v in f.values() if v[1])
    return tot_l, hit_l, tot_f, hit_f, tot_b, hit_b


# --------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(
        description="orbprofile callgrind output -> lcov .info coverage")
    ap.add_argument("profiles", nargs="+",
                    help="callgrind file(s) from 'orbprofile -z'; several are merged")
    ap.add_argument("-e", "--elf", required=True, help="the same ELF given to orbprofile")
    ap.add_argument("-o", "--output", default="coverage.info", help="lcov output file")
    ap.add_argument("-i", "--include", action="append", default=[],
                    help="only source paths containing this text (repeatable), e.g. -i Src/")
    ap.add_argument("-x", "--exclude", action="append", default=[],
                    help="skip source paths containing this text (repeatable), e.g. -x Drivers/")
    ap.add_argument("-s", "--strip", default="",
                    help="prefix to remove from source paths in the report")
    ap.add_argument("-t", "--test-name", default="etm", help="lcov test name")
    a = ap.parse_args()

    counts = defaultdict(int)
    branches = {}
    for p in a.profiles:
        n = parse_callgrind(p, counts, branches)
        print(f"{p}: {n} executed addresses", file=sys.stderr)
    if not counts:
        sys.exit("no execution data found - did orbprofile receive trace?")

    def keep(path):
        if a.include and not any(s in path for s in a.include):
            return False
        return not any(s in path for s in a.exclude)

    ranges, funcs = read_elf(a.elf)
    lines, fns, brs = build(ranges, funcs, counts, branches, keep)
    if not lines:
        sys.exit("no source files left after --include/--exclude filtering")

    tl, hl, tf, hf, tb, hb = write_lcov(a.output, lines, fns, brs, a.test_name, a.strip)
    pct = lambda h, t: (100.0 * h / t) if t else 0.0
    msg = (f"wrote {a.output}: {len(lines)} files, "
           f"lines {hl}/{tl} ({pct(hl, tl):.1f}%), "
           f"functions {hf}/{tf} ({pct(hf, tf):.1f}%)")
    if tb:
        msg += f", branches {hb}/{tb} ({pct(hb, tb):.1f}%)"
    else:
        msg += ", no branch data (orbprofile without jcnd output?)"
    print(msg, file=sys.stderr)


if __name__ == "__main__":
    main()
