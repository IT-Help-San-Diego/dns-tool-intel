#!/usr/bin/env bash
# Local Lighthouse gauge — run on a FAST developer machine (not CI) to see the
# TRUE desktop/mobile score, matching what web.dev/PageSpeed Insights reports.
# Uses the --local floors (tighter: performance 97, others 100) so a real code
# regression is caught here before it reaches the CI container-relative guard.
#
# Usage:
#   bash tests/lighthouse/run-local.sh [url]
# Defaults to the local server at http://localhost:5000/ — or pass the live site:
#   bash tests/lighthouse/run-local.sh https://dnstool.it-help.tech/
set -euo pipefail

URL="${1:-http://localhost:5000/}"

echo "=== Desktop (true score, should be ~100) ==="
npx lighthouse "$URL" \
  --preset=desktop \
  --output=json \
  --output-path=./lighthouse-local-desktop.json \
  --only-categories=performance,accessibility,best-practices,seo \
  --quiet
node tests/lighthouse/assert-scores.mjs ./lighthouse-local-desktop.json --local

echo
echo "=== Mobile (should be ~97) ==="
npx lighthouse "$URL" \
  --output=json \
  --output-path=./lighthouse-local-mobile.json \
  --only-categories=performance,accessibility,best-practices,seo \
  --quiet
node tests/lighthouse/assert-scores.mjs ./lighthouse-local-mobile.json --local
