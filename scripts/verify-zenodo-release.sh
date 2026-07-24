#!/bin/bash
# Post-release Zenodo verification — confirms the GitHub → Zenodo auto-archive
# for a tagged release actually landed AND carries the right metadata.
# Usage: bash scripts/verify-zenodo-release.sh X.Y.Z [--wait]
#
# Queries the live concept record (no auth needed) and checks that the LATEST
# version under concept DOI 10.5281/zenodo.19468134:
#   1. archives the vX.Y.Z source zip (…/dns-tool-intel-vX.Y.Z.zip), and
#   2. declares metadata version X.Y.Z.
# Check 2 is the one that would have caught v26.50.05: Zenodo archived the
# right zip but the tag commit lacked the release-gate bump, so the deposit
# metadata stayed frozen at 26.46.14.
#
# --wait: poll up to 15 minutes. Zenodo ingestion is async — it starts when
# GitHub Actions publishes the Release, typically minutes after the tag push.
#
# Exit codes: 0 = verified; 1 = not verified (not ingested yet, or metadata
# mismatch — the output says which).

set -euo pipefail
cd "$(dirname "$0")/.."

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

pass() { echo -e "${GREEN}PASS${NC} — $1"; }
fail() { echo -e "${RED}FAIL${NC} — $1"; exit 1; }
info() { echo -e "${YELLOW}INFO${NC} — $1"; }

VERSION="${1:-}"
if [ -z "$VERSION" ]; then
  echo "Usage: bash scripts/verify-zenodo-release.sh X.Y.Z [--wait]"
  echo "  Version must not have a leading 'v'"
  exit 1
fi
if [[ "$VERSION" == v* ]]; then
  fail "Version must NOT have a leading 'v' (got: $VERSION). Use: ${VERSION#v}"
fi

# Concept record of the live lineage. PERMANENT — must match CITATION.cff doi.
CONCEPT_RECID="19468134"

ATTEMPTS=1
SLEEP_SECS=30
if [ "${2:-}" = "--wait" ]; then
  ATTEMPTS=30 # 30 × 30s ≈ 15 minutes
fi

info "Checking latest version under concept DOI 10.5281/zenodo.${CONCEPT_RECID} for v${VERSION}..."

for (( i=1; i<=ATTEMPTS; i++ )); do
  RESULT=$(python3 - "$CONCEPT_RECID" "$VERSION" <<'PY'
import json, sys, urllib.request
recid, ver = sys.argv[1], sys.argv[2]
url = "https://zenodo.org/api/records/%s" % recid
try:
    with urllib.request.urlopen(url, timeout=30) as r:
        d = json.load(r)
except Exception as e:
    print("FETCH_ERROR %s" % e)
    sys.exit(0)
meta_ver = (d.get("metadata") or {}).get("version") or ""
files = [f.get("key", "") for f in (d.get("files") or [])]
doi = d.get("doi", "")
zip_ok = any(k.endswith("-v%s.zip" % ver) for k in files)
meta_ok = meta_ver.lstrip("v") == ver
if zip_ok and meta_ok:
    print("OK %s" % doi)
elif zip_ok:
    print("METADATA_MISMATCH doi=%s metadata.version=%s expected=%s" % (doi, meta_ver, ver))
else:
    print("NOT_ARCHIVED latest_doi=%s latest_version=%s files=%s" % (doi, meta_ver, ";".join(files)))
PY
)
  case "$RESULT" in
    OK*)
      VERSION_DOI="${RESULT#OK }"
      pass "Zenodo archived v${VERSION} with correct metadata"
      echo "  Version DOI: ${VERSION_DOI}"
      echo "  Record:      https://doi.org/${VERSION_DOI}"
      exit 0
      ;;
    METADATA_MISMATCH*)
      echo "  $RESULT"
      fail "The v${VERSION} zip is archived but the deposit metadata declares a DIFFERENT version — the tag was cut without the release-gate bump (the v26.50.05 failure mode). Waiting will not fix this: cut a fresh gated release."
      ;;
    *)
      if [ "$i" -lt "$ATTEMPTS" ]; then
        echo "  attempt ${i}/${ATTEMPTS}: not ingested yet (${RESULT}) — retrying in ${SLEEP_SECS}s..."
        sleep "$SLEEP_SECS"
      else
        echo "  $RESULT"
        if [ "$ATTEMPTS" -eq 1 ]; then
          fail "v${VERSION} not found as the latest Zenodo version. Ingestion is async — retry with: bash scripts/verify-zenodo-release.sh ${VERSION} --wait"
        else
          fail "v${VERSION} still not the latest Zenodo version after ~15 min. Check the GitHub Release exists, then https://zenodo.org/account/settings/github/ for ingestion errors."
        fi
      fi
      ;;
  esac
done
