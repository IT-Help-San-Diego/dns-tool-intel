#!/usr/bin/env python3
"""Read gosec `-fmt json` from stdin; emit one `file|rule|hash` line per issue.

The hash is a content hash of the *flagged statement* (the source line gosec
identified), so the suppression ledger keys on CODE CONTENT rather than the
line number. An unrelated edit above a finding moves its line number but not
its content, so a content key stays stable where a line key would drift. If a
finding is fixed or its code changes, the content changes and the hash changes,
so the ledger entry goes stale and gets re-reviewed — which is the whole point.
"""
import hashlib
import json
import sys


def main() -> int:
    try:
        data = json.load(sys.stdin)
    except (json.JSONDecodeError, ValueError) as exc:
        print(f"gosec_hash: stdin is not valid gosec JSON: {exc}", file=sys.stderr)
        return 2

    for issue in data.get("Issues", []):
        path = issue["file"].split("/go-server/", 1)[-1]
        rule = issue["rule_id"]
        line_no = issue["line"]
        content = ""
        for ln in issue.get("code", "").splitlines():
            if ln.startswith(line_no + ":"):
                content = ln.split(":", 1)[1].strip()
                break
        if not content:
            content = issue.get("details", "")
        digest = hashlib.sha256(content.encode()).hexdigest()[:16]
        print(f"{path}|{rule}|{digest}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
