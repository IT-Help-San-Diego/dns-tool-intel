#!/usr/bin/env python3
"""Remap assemble_v2.py's line ranges for the current results.html.

The generator's SOURCE_LINE_COUNT (7045) predates 15 lines of drift on main.
This script aligns old line numbers to new via difflib against the last
generator-touched revision, remaps every range boundary, updates
SOURCE_LINE_COUNT, then runs the generator so its own coverage assertion
verifies the remap. Never hand-guesses the shift — measure the mapping.
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
REPO = ROOT / "go-server"
GEN = REPO / "tools" / "report-mint" / "assemble_v2.py"
SRC = REPO / "templates" / "results.html"

LAST_GEN_COMMIT = "f45afa617"

old = subprocess.run(
    ["git", "-C", str(REPO.parent), "show",
     f"{LAST_GEN_COMMIT}:go-server/templates/results.html"],
    capture_output=True, text=True, check=True,
).stdout.split("\n")

new = SRC.read_text().split("\n")
print(f"old lines: {len(old)}, new lines: {len(new)}")

import difflib
sm = difflib.SequenceMatcher(a=old, b=new, autojunk=False)
# old_line_index (0-based) -> new_line_index (0-based)
omap = {}
for tag, i1, i2, j1, j2 in sm.get_opcodes():
    if tag == "equal":
        for k in range(i2 - i1):
            omap[i1 + k] = j1 + k
    elif tag in ("replace", "delete"):
        # map to the position just before the edit (best-effort anchor)
        for k in range(i2 - i1):
            omap.setdefault(i1 + k, j1)
    # insert: nothing on the old side

def map_line(old_1based: int) -> int:
    idx = old_1based - 1
    if idx in omap:
        return omap[idx] + 1
    # find nearest mapped old line below
    for k in range(idx, -1, -1):
        if k in omap:
            return omap[k] + 1
    return 1

src = GEN.read_text()

new_count = len(new)
src = re.sub(r"SOURCE_LINE_COUNT = \d+",
             f"SOURCE_LINE_COUNT = {new_count}", src, count=1)

# Remap every range tuple. Ranges are written as (a, b) inside ranges= tuples.
def remap_range(m: re.Match) -> str:
    a, b = int(m.group(1)), int(m.group(2))
    na, nb = map_line(a), map_line(b)
    print(f"  range ({a}, {b}) -> ({na}, {nb})")
    return f"({na}, {nb})"

src, n = re.subn(r"\((\d+), (\d+)\)", remap_range, src)
print(f"remapped {n} ranges; SOURCE_LINE_COUNT -> {new_count}")

GEN.write_text(src)

# Run the generator with a clean environment (PYTHONPATH poisoning hazard).
env = {"PATH": "/usr/bin:/bin:/opt/homebrew/bin", "HOME": str(Path.home())}
r = subprocess.run([sys.executable, str(GEN)], cwd=str(REPO),
                   capture_output=True, text=True, env=env)
print("generator exit:", r.returncode)
if r.stdout.strip():
    print(r.stdout.strip()[:500])
if r.stderr.strip():
    print("STDERR:", r.stderr.strip()[:800])

# Verify the new field made it into the generated v2 template.
dst = (REPO / "templates" / "results_v2.html").read_text()
print("v2 contains 'attainable':", "attainable" in dst)
