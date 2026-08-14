#!/usr/bin/env python3
"""Verify a suppression ledger's `guard` fields against the live source.

A suppression's reasoning is usually about a GUARD above the flagged statement
(e.g. a validator the exec depends on), not the statement itself. If that guard
is deleted or changed, the statement may be byte-identical but the suppression
is no longer valid. Each ledger entry may carry a `guard` field of the form
`file|symbol|hash`; this helper re-locates the symbol in the file, re-hashes its
DECLARATION THROUGH ITS CLOSING BRACE (the whole validator — body included —
not just the declaration's first line), and reports any entry whose guard hash
no longer matches (or whose symbol has vanished).

Some rule classes (G204 exec, G304 path traversal, G402 TLS) are only safe
because an upstream validator gates the flagged statement. For those, `guard`
is REQUIRED — an entry without one is fail-open and is reported here. A
statement-alone claim (e.g. G101 "this is a URL constant, not a credential")
has no upstream validator and may omit `guard`.

Reads the ledger directly (flat YAML line format). Emits one line per STALE or
MISSING guard as `rule|file|symbol`; exits non-zero if any are found.

Usage: guard_check.py --ledger security/suppressions.yaml --root /abs/repo
"""
import argparse
import hashlib
import sys

# Rules whose safety claim is "input is validated upstream" — a guard MUST be
# named so the gate can prove the validator still exists. Without a guard the
# claim is unverifiable prose and the suppression is fail-open.
REQUIRED_GUARD_RULES = {"G204", "G304", "G402"}


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


def declaration_block(path, decl):
    """Return the source text of the declaration at 1-indexed `decl`.

    Keyed on the Go TOKEN, not brace presence: only a `func` has a body whose
    content must be hashed (gutting it to `return true` must change the hash),
    so a func hashes from its declaration line through the closing brace at the
    declaration's indent level. A `var`/`const`/`type` is a single-line
    declaration and hashes as its line alone — so brace characters that are
    REGEX syntax (e.g. `{0,61}` in a validator pattern) or a composite-literal
    opener are never misread as Go block syntax."""
    with open(path, "r", encoding="utf-8") as fh:
        lines = fh.readlines()
    first = lines[decl - 1]
    if not first.lstrip().startswith(("func ", "func (")):
        return first.strip()  # var/const/type — hash the line
    if "}" in first:
        return first.strip()  # one-liner func — { ... } on the decl line
    indent = len(first) - len(first.lstrip())
    block = [first]
    for i in range(decl, len(lines)):
        line = lines[i]
        block.append(line)
        stripped = line.lstrip()
        if stripped.startswith("}") and (len(line) - len(line.lstrip())) == indent:
            break
    return "".join(block).strip()


def parse_ledger(path):
    """Parse the flat YAML ledger into a list of entry dicts."""
    entries = []
    cur = None
    with open(path, "r", encoding="utf-8") as fh:
        for raw in fh:
            line = raw.strip()
            if line.startswith("- rule:"):
                if cur is not None:
                    entries.append(cur)
                cur = {"rule": line.split(":", 1)[1].strip(), "guard": None}
            elif cur is not None and line.startswith("guard:"):
                val = line.split(":", 1)[1].strip().strip('"')
                parts = val.split("|")
                if len(parts) == 3:
                    cur["guard"] = (parts[0], parts[1], parts[2])
    if cur is not None:
        entries.append(cur)
    return entries


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--ledger", required=True)
    ap.add_argument("--root", required=True)
    args = ap.parse_args()
    root = args.root.rstrip("/") + "/"

    stale = 0
    for e in parse_ledger(args.ledger):
        rule = e["rule"]
        if e["guard"] is None:
            if rule in REQUIRED_GUARD_RULES:
                print(f"{rule}|<no guard>|—\tMISSING GUARD (required for {rule})")
                stale += 1
            continue  # statement-alone claim — no upstream validator to check
        gfile, gsymbol, ghash = e["guard"]
        path = root + gfile
        decl = find_declaration_line(path, gsymbol)
        if decl is None:
            print(f"{rule}|{gfile}|{gsymbol}\tMISSING (symbol not found)")
            stale += 1
            continue
        content = declaration_block(path, decl)
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
