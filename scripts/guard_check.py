#!/usr/bin/env python3
"""Verify a suppression ledger's `guard` fields against the live source.

A suppression's reasoning is usually about a GUARD above the flagged statement
(e.g. a validator the exec depends on), not the statement itself. If that guard
is deleted or changed, the statement may be byte-identical but the suppression
is no longer valid. Each ledger entry may carry a `guard` field of the form
`file|symbol|hash`; this helper re-locates the symbol in the file, re-hashes its
declaration line, and reports any entry whose guard hash no longer matches (or
whose symbol has vanished).

Reads the ledger directly (flat YAML line format). Emits one line per STALE or
MISSING guard as `rule|file|symbol`; exits non-zero if any are found.

Usage: guard_check.py --ledger security/suppressions.yaml --root /abs/repo
"""
import argparse
import hashlib
import sys


def find_declaration_line(path, symbol):
    """Return the 1-indexed line containing the symbol's declaration, or None."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            for i, line in enumerate(fh, 1):
                if symbol in line and any(
                    kw in line for kw in ("var ", "func ", "const ", "type ")
                ):
                    return i
    except OSError:
        return None
    return None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--ledger", required=True)
    ap.add_argument("--root", required=True)
    args = ap.parse_args()
    root = args.root.rstrip("/") + "/"

    # Parse the flat ledger: track the current rule, collect guard fields.
    entries = []
    rule = ""
    with open(args.ledger, "r", encoding="utf-8") as fh:
        for raw in fh:
            line = raw.strip()
            if line.startswith("- rule:"):
                rule = line.split(":", 1)[1].strip()
            elif line.startswith("guard:") and rule:
                val = line.split(":", 1)[1].strip().strip('"')
                parts = val.split("|")
                if len(parts) == 3:
                    entries.append((rule, parts[0], parts[1], parts[2]))

    stale = 0
    for rule, gfile, gsymbol, ghash in entries:
        path = root + gfile
        decl = find_declaration_line(path, gsymbol)
        if decl is None:
            print(f"{rule}|{gfile}|{gsymbol}\tMISSING (symbol not found)")
            stale += 1
            continue
        with open(path, "r", encoding="utf-8") as fh:
            content = fh.readlines()[decl - 1].strip()
        cur = hashlib.sha256(content.encode()).hexdigest()[:16]
        if cur != ghash:
            print(f"{rule}|{gfile}|{gsymbol}\tCHANGED (hash {cur} != {ghash})")
            stale += 1

    if stale:
        print(
            f"guard_check: {stale} guard(s) stale or missing — re-reason the "
            "suppression before it silently continues to suppress.",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
