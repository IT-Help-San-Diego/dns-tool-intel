#!/usr/bin/env python3
"""Remap assemble_v2.py's line ranges for the current results.html.

Idempotent: every run starts from the pristine generator at f45afa617
(the last generator-touched revision), difflib-aligns old line numbers to
the current results.html, remaps every range boundary (including the
computed tail (N, SOURCE_LINE_COUNT)), updates SOURCE_LINE_COUNT, then runs
the generator so its own every-line-exactly-once coverage proof verifies
the remap. Never hand-guess the shift — measure the mapping.
"""
from __future__ import annotations

import difflib
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
REPO = ROOT / "go-server"
GEN = REPO / "tools" / "report-mint" / "assemble_v2.py"
SRC = REPO / "templates" / "results.html"
PRISGIT = "f45afa617"

git = ["git", "-C", str(REPO.parent)]

old = subprocess.run(
    git + ["show", f"{PRISGIT}:go-server/templates/results.html"],
    capture_output=True, text=True, check=True,
).stdout.split("\n")
new = SRC.read_text().split("\n")
print(f"old lines: {len(old)}, new lines: {len(new)}")

sm = difflib.SequenceMatcher(a=old, b=new, autojunk=False)
omap = {}
for tag, i1, i2, j1, j2 in sm.get_opcodes():
    if tag == "equal":
        for k in range(i2 - i1):
            omap[i1 + k] = j1 + k
    elif tag in ("replace", "delete"):
        for k in range(i2 - i1):
            omap.setdefault(i1 + k, j1)

def map_line(old_1based: int) -> int:
    idx = old_1based - 1
    if idx in omap:
        return omap[idx] + 1
    for k in range(idx, -1, -1):
        if k in omap:
            return omap[k] + 1
    return 1

# Always start from the pristine generator so repeated runs are idempotent.
src = subprocess.run(
    git + ["show", f"{PRISGIT}:go-server/tools/report-mint/assemble_v2.py"],
    capture_output=True, text=True, check=True,
).stdout

new_count = len(new)
src = re.sub(r"SOURCE_LINE_COUNT = \d+",
             f"SOURCE_LINE_COUNT = {new_count}", src, count=1)

def remap_range(m: re.Match) -> str:
    a, b = int(m.group(1)), int(m.group(2))
    na, nb = map_line(a), map_line(b)
    print(f"  range ({a}, {b}) -> ({na}, {nb})")
    return f"({na}, {nb})"

src, n = re.subn(r"\((\d+), (\d+)\)", remap_range, src)

def remap_tail(m: re.Match) -> str:
    a = int(m.group(1))
    na = map_line(a)
    print(f"  tail ({a}, SOURCE_LINE_COUNT) -> ({na}, SOURCE_LINE_COUNT)")
    return f"({na}, SOURCE_LINE_COUNT)"

src, nt = re.subn(r"\((\d+), SOURCE_LINE_COUNT\)", remap_tail, src)
print(f"remapped {n} ranges + {nt} tail; SOURCE_LINE_COUNT -> {new_count}")

GEN.write_text(src)

env = {"PATH": "/usr/bin:/bin:/opt/homebrew/bin", "HOME": str(Path.home())}
r = subprocess.run([sys.executable, str(GEN)], cwd=str(REPO),
                   capture_output=True, text=True, env=env)
print("generator exit:", r.returncode)
if r.stdout.strip():
    print(r.stdout.strip()[:400])
if r.stderr.strip():
    print("STDERR:", r.stderr.strip()[:600])

dst = (REPO / "templates" / "results_v2.html").read_text()
print("v2 contains 'attainable':", "attainable" in dst)
