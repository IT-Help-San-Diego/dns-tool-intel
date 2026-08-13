#!/usr/bin/env python3
"""Read gosec `-fmt json` from stdin; emit one `file|rule|hash` line per issue.

The path is made REPO-ROOT-RELATIVE (via --root) so the key is identical on a
dev Mac, in CI, and on the EC2 box — an absolute path would make the key
machine-dependent. The hash is a content hash of the flagged statement, so the
suppression ledger keys on CODE CONTENT rather than line number.

If the flagged line cannot be extracted from gosec's `code` block (e.g. a gosec
version bump changes the format), this exits non-zero rather than silently
falling back to the generic `details` string — a generic fallback would collapse
every finding of a rule into one key and let a single entry suppress all of
them.

Usage: gosec_hash.py --root /abs/path/to/repo < gosec.json
"""
import argparse
import hashlib
import json
import sys


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", required=True, help="repo root (absolute path)")
    args = ap.parse_args()
    root = args.root.rstrip("/") + "/"

    try:
        data = json.load(sys.stdin)
    except (json.JSONDecodeError, ValueError) as exc:
        print(f"gosec_hash: stdin is not valid gosec JSON: {exc}", file=sys.stderr)
        return 2

    fallbacks = 0
    for issue in data.get("Issues", []):
        path = issue["file"]
        if not path.startswith(root):
            print(
                f"gosec_hash: file '{path}' is not under repo root '{root}' — "
                "refusing to key on an absolute path.",
                file=sys.stderr,
            )
            return 2
        rel = path[len(root):]

        rule = issue["rule_id"]
        # "line" is a single line ("50") or a range ("50-51"); the flagged
        # statement is the WHOLE range, so hash every line in it (not just the
        # first, which two different findings may share).
        line_spec = issue["line"]
        start_s, _, end_s = line_spec.partition("-")
        if not end_s:
            end_s = start_s
        content_parts = []
        for ln in issue.get("code", "").splitlines():
            num = ln.split(":", 1)[0].strip()
            if num.isdigit() and int(start_s) <= int(num) <= int(end_s):
                content_parts.append(ln.split(":", 1)[1].strip())
        content = "\n".join(content_parts)
        if not content:
            fallbacks += 1
            print(
                f"gosec_hash: WARNING — flagged line {line_spec} not found in "
                f"code block for {rel} ({rule}); falling back to generic "
                f"details. This can collapse distinct findings into one key.",
                file=sys.stderr,
            )
            content = issue.get("details", "")

        digest = hashlib.sha256(content.encode()).hexdigest()[:16]
        print(f"{rel}|{rule}|{digest}")

    if fallbacks:
        print(
            f"gosec_hash: {fallbacks} finding(s) used the generic-details "
            "fallback — treat these keys with suspicion.",
            file=sys.stderr,
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
