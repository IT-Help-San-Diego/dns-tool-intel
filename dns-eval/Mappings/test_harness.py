#!/usr/bin/env python3
"""
Explicit-path regression + drift net for the tri-state ICSAE harness.

- Producer fixtures -> normalize_input.py -> EXACT observations/context match.
  A producer vocabulary rename emits null where the fixture expects a value,
  so this is the drift alarm for the normalizer's read of the tool's status
  vocabulary.
- Observation fixtures -> evaluate.py -> EXACT per-control verdicts and counts.
  Pins the tri-state grading: null never fails, null in applies_when ->
  not_measured (not not_applicable), measured false still fails, the
  denominator excludes not_measured.

Run: python3 dns-eval/Mappings/test_harness.py   (repo root or anywhere;
paths are explicit -- never the mtime-default discovery mode)
"""
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))       # .../dns-eval/Mappings
EVAL_ROOT = os.path.dirname(HERE)                      # .../dns-eval
TMP = os.path.join(HERE, "fixtures", "tmp")
os.makedirs(TMP, exist_ok=True)

def run(args):
    r = subprocess.run([sys.executable] + args, cwd=EVAL_ROOT,
                       capture_output=True, text=True)
    if r.returncode != 0:
        raise AssertionError(f"{' '.join(args)} exited {r.returncode}:\n{r.stdout}\n{r.stderr}")
    return r.stdout

failures = []

def check(name, got, want):
    if got != want:
        failures.append((name, got, want))

def load(p):
    with open(p) as f:
        return json.load(f)

for name in ["good", "absent", "na"]:
    src = os.path.join(HERE, "fixtures", "producers", f"{name}.json")
    exp = load(os.path.join(HERE, "fixtures", "expected", f"producers-{name}.json"))
    out = os.path.join(TMP, f"{name}-normalized.json")
    run(["Mappings/normalize_input.py", src, out])
    got = load(out)
    check(f"producer-{name} observations", got["observations"], exp["observations"])
    check(f"producer-{name} context", got["context"], exp["context"])

for name in ["all-true-mail", "all-false-mail", "all-null", "cs-mixed"]:
    src = os.path.join(HERE, "fixtures", "observations", f"{name}.json")
    exp = load(os.path.join(HERE, "fixtures", "expected", f"observations-{name}.json"))
    out = os.path.join(TMP, f"{name}-results.json")
    run(["Mappings/evaluate.py", src, out])
    res = load(out)
    statuses = {r["id"]: r["status"] for r in res["results"]}
    check(f"{name} verdicts", statuses, exp["verdicts"])
    for k in ("passed_count", "failed_count", "na_count", "not_measured_count",
              "measured_controls", "null_observations"):
        check(f"{name} {k}", res[k], exp[k])

if failures:
    for name, got, want in failures:
        print(f"FAIL {name}\n  got:  {json.dumps(got, sort_keys=True)}\n  want: {json.dumps(want, sort_keys=True)}")
    sys.exit(1)
print("ALL HARNESS FIXTURE CHECKS PASSED")
