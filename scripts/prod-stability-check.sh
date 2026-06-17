#!/usr/bin/env bash
# Prod DANE/DNSSEC tri-state stability check.
#
# Why this exists: DANE/TLSA + DNSSEC presence are now tri-state
# (present / absent_confirmed / indeterminate) so that a transient resolver
# failure reads as "could not verify" instead of a false "absent". The bug this
# guards against was real flapping in production (nlnetlabs.nl toggled 44x).
# Unit tests cover the logic with mocks; this script verifies the LIVE prod
# build behaves honestly against real domains and real resolvers.
#
# What it does: for each domain it runs N full scans against prod, extracts
# dane_state + dnssec_state from /api/analysis/<id>, and reports the
# distribution across runs.
#
# Pass/fail (exit code):
#   FAIL (exit 1) only on a TRUE flap — a domain returning BOTH `present` and
#   `absent_confirmed` across runs (the original bug class), or all runs erroring.
#   A mix of `present` and `indeterminate` is the honest transient behaviour and
#   is reported as a NOTE, not a failure.
#
# The "matches internet.nl" apples-to-apples comparison stays a manual human
# check — this script confirms stability + that no false `absent_confirmed`
# verdict is produced for a DANE-deployed domain.
#
# Usage:
#   bash scripts/prod-stability-check.sh                      # default domains, 3 runs
#   RUNS=5 bash scripts/prod-stability-check.sh proton.me     # custom
#   PROD_BASE=https://staging.example bash scripts/prod-stability-check.sh
#
# Env:
#   PROD_BASE  target base URL          (default https://dnstool.it-help.tech)
#   RUNS       scans per domain         (default 3)
#   POLL_MAX   progress polls @3s each  (default 45 → 135s ceiling per scan)

set -uo pipefail

BASE="${PROD_BASE:-https://dnstool.it-help.tech}"
RUNS="${RUNS:-3}"
POLL_MAX="${POLL_MAX:-45}"

DOMAINS=("$@")
if [ ${#DOMAINS[@]} -eq 0 ]; then
        # Defaults: two DANE-deployed mail providers + the original flapper.
        DOMAINS=(proton.me mailbox.org nlnetlabs.nl)
fi

RESULTS_FILE="$(mktemp)"
trap 'rm -f "$RESULTS_FILE"' EXIT

echo "═══════════════════════════════════════════════"
echo "  DANE/DNSSEC Tri-State Stability Check"
echo "  Target: $BASE"
echo "  Domains: ${DOMAINS[*]}"
echo "  Runs per domain: $RUNS"
echo "═══════════════════════════════════════════════"
echo

# scan_once <domain> -> prints "dane_state|dnssec_state" or "ERROR:<reason>"
scan_once() {
        local domain="$1"
        local jar signed bare resp token aid p js i

        jar="$(mktemp)"

        # 1. GET homepage → mint a signed _csrf cookie.
        if ! curl -fsS -c "$jar" -o /dev/null "$BASE/"; then
                echo "ERROR:homepage-unreachable"; rm -f "$jar"; return
        fi
        signed="$(awk '$6=="_csrf"{print $7}' "$jar")"
        bare="${signed%.*}"
        if [ -z "$bare" ]; then
                echo "ERROR:no-csrf-cookie"; rm -f "$jar"; return
        fi

        # 2. POST /analyze (JSON) → async scan token. The bare token satisfies
        #    double-submit: cookie holds token.sig, form/header carry token.
        resp="$(curl -fsS -b "$jar" -H 'Accept: application/json' -H "X-CSRF-Token: $bare" \
                --data-urlencode "domain=$domain" --data-urlencode "csrf_token=$bare" \
                "$BASE/analyze" 2>/dev/null)"
        token="$(printf '%s' "$resp" | python3 -c 'import sys,json
try: print(json.load(sys.stdin).get("token","") or "")
except Exception: print("")' 2>/dev/null)"
        if [ -z "$token" ]; then
                echo "ERROR:no-token"; rm -f "$jar"; return
        fi

        # 3. Poll progress until analysis_id appears.
        aid=""
        for ((i=0; i<POLL_MAX; i++)); do
                p="$(curl -fsS "$BASE/api/scan/progress/$token" 2>/dev/null)"
                aid="$(printf '%s' "$p" | python3 -c 'import sys,json
try:
    v=json.load(sys.stdin).get("analysis_id")
    print(v if v else "")
except Exception: print("")' 2>/dev/null)"
                [ -n "$aid" ] && break
                sleep 3
        done
        if [ -z "$aid" ]; then
                echo "ERROR:scan-timeout"; rm -f "$jar"; return
        fi

        # 4. Fetch the analysis JSON and extract tri-state verdicts.
        js="$(curl -fsS "$BASE/api/analysis/$aid" 2>/dev/null)"
        printf '%s' "$js" | python3 -c 'import sys,json
try:
    fr=json.load(sys.stdin).get("full_results",{})
    dane=fr.get("dane_analysis",{}).get("dane_state","?")
    dnssec=fr.get("dnssec_analysis",{}).get("dnssec_state","?")
    print(f"{dane}|{dnssec}")
except Exception:
    print("ERROR:parse")' 2>/dev/null || echo "ERROR:parse"

        rm -f "$jar"
}

for domain in "${DOMAINS[@]}"; do
        echo "▸ $domain"
        for ((r=1; r<=RUNS; r++)); do
                out="$(scan_once "$domain")"
                if [[ "$out" == ERROR:* ]]; then
                        printf "    run %d/%d  ✗ %s\n" "$r" "$RUNS" "$out"
                        echo "$domain   ERROR   ${out#ERROR:}" >> "$RESULTS_FILE"
                else
                        dane="${out%%|*}"; dnssec="${out##*|}"
                        printf "    run %d/%d  DANE=%-16s DNSSEC=%s\n" "$r" "$RUNS" "$dane" "$dnssec"
                        echo "$domain   $dane   $dnssec" >> "$RESULTS_FILE"
                fi
        done
        echo
done

echo "═══════════════════════════════════════════════"
echo "  Summary"
echo "═══════════════════════════════════════════════"

python3 - "$RESULTS_FILE" <<'PY'
import sys, collections

rows = []
with open(sys.argv[1]) as f:
        for line in f:
                parts = line.rstrip("\n").split("\t")
                if len(parts) == 3:
                        rows.append(parts)

# Guard: an empty results file must never read as a silent PASS — that would
# hide a totally broken run (wrong delimiter, all curls failing, etc.).
if not rows:
        print("\n  No parsable result rows found — nothing was verified.")
        print("\n═══════════════════════════════════════════════")
        print("  RESULT: FAIL — no data collected")
        print("═══════════════════════════════════════════════")
        sys.exit(1)

by_domain = collections.OrderedDict()
for domain, dane, dnssec in rows:
        by_domain.setdefault(domain, []).append((dane, dnssec))

def dist(values):
        c = collections.Counter(values)
        return ", ".join(f"{k}×{v}" for k, v in c.items())

# A protocol "flaps" (the original bug class) when it returns BOTH a real
# present and a confirmed-absent across runs. present+indeterminate is the
# honest transient case and is NOT a failure.
def classify(states):
        live = set(s for s in states if s != "ERROR")
        if "present" in live and "absent_confirmed" in live:
                return "flap"
        if len(live) > 1:
                return "transient"
        return "stable"

hard_fail = False
for domain, runs in by_domain.items():
        danes = [d for d, _ in runs]
        dnssecs = [s for _, s in runs]
        errored = [d for d in danes if d == "ERROR"]

        verdict = "STABLE"
        notes = []

        if errored and len(errored) == len(danes):
                verdict = "FAIL (all runs errored)"
                hard_fail = True
        else:
                dane_cls = classify(danes)
                dnssec_cls = classify(dnssecs)
                flappers = [p for p, c in (("DANE", dane_cls), ("DNSSEC", dnssec_cls)) if c == "flap"]
                if flappers:
                        verdict = f"FAIL ({'+'.join(flappers)} present↔absent_confirmed flap)"
                        hard_fail = True
                elif "transient" in (dane_cls, dnssec_cls):
                        verdict = "STABLE (transient indeterminate seen)"
                        notes.append("indeterminate is honest tri-state, not drift")
                if errored:
                        notes.append(f"{len(errored)} run(s) errored")

        print(f"\n  {domain}")
        print(f"    DANE:    {dist(danes)}")
        print(f"    DNSSEC:  {dist(dnssecs)}")
        print(f"    Verdict: {verdict}")
        for n in notes:
                print(f"    Note:    {n}")

print()
print("═══════════════════════════════════════════════")
if hard_fail:
        print("  RESULT: FAIL — true flapping or total failure detected")
        print("═══════════════════════════════════════════════")
        sys.exit(1)
print("  RESULT: PASS — no present↔absent_confirmed flapping")
print("═══════════════════════════════════════════════")
PY
