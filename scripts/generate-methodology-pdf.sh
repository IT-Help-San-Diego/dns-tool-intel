#!/bin/bash
# Generate the methodology PDF from the HTML source using WeasyPrint.
# Usage: bash scripts/generate-methodology-pdf.sh [VERSION]
#
# If VERSION is provided, updates the version in both .md and .html before
# generating the PDF. If omitted, generates from current content.
#
# Prerequisites: weasyprint (listed in pyproject.toml)
# Logo asset: static/images/owl-signature.png (Owl of Athena — dark background, premium version)
#
# This MUST be run after every version bump that touches
# docs/dns-tool-methodology.html or docs/dns-tool-methodology.md

set -euo pipefail
cd "$(dirname "$0")/.."

VERSION="${1:-}"

if [ -n "$VERSION" ]; then
  source scripts/lib/require-gnu-sed.sh
  echo "Updating methodology version to ${VERSION}..."

  "$SED" -i -E "s/Version [0-9]+\.[0-9]+\.[0-9]+/Version ${VERSION}/" docs/dns-tool-methodology.md
  "$SED" -i -E "s/version      = \{[0-9]+\.[0-9]+\.[0-9]+\}/version      = {${VERSION}}/" docs/dns-tool-methodology.md
  "$SED" -i -E "s/DNS Tool v[0-9]+\.[0-9]+\.[0-9]+/DNS Tool v${VERSION}/" docs/dns-tool-methodology.md

  "$SED" -i -E "s/Version<\/span>\&ensp;[0-9]+\.[0-9]+\.[0-9]+/Version<\/span>\&ensp;${VERSION}/" docs/dns-tool-methodology.html
  "$SED" -i -E "s/version\&nbsp;\&nbsp;\&nbsp;\&nbsp;\&nbsp;\&nbsp;= \{[0-9]+\.[0-9]+\.[0-9]+\}/version\&nbsp;\&nbsp;\&nbsp;\&nbsp;\&nbsp;\&nbsp;= {${VERSION}}/" docs/dns-tool-methodology.html
  "$SED" -i -E "s/DNS Tool v[0-9]+\.[0-9]+\.[0-9]+/DNS Tool v${VERSION}/" docs/dns-tool-methodology.html

  echo "Version updated in .md and .html"
fi

# Prose sync check: the .md and .html are parallel hand-maintained copies of
# the same document. The PDF is built from the .html only. If the .md is
# edited without the .html, the PDF republishes stale text under a new
# version — the same class as the stale main.min.js that sat three months
# behind its source. This check compares a fingerprint of the calibration
# section in both files; it catches the case where one was edited and the
# other wasn't, which is exactly what happened in PR #236.
echo "Checking .md ↔ .html prose sync..."
MD_SIGNALS=$(grep -c 'severity-weighted\|shrinkage-formula behavior\|single-outcome-class\|Field Replication' docs/dns-tool-methodology.md 2>/dev/null || echo 0)
HTML_SIGNALS=$(grep -c 'severity-weighted\|shrinkage-formula behavior\|single-outcome-class\|Field Replication' docs/dns-tool-methodology.html 2>/dev/null || echo 0)
if [ "$MD_SIGNALS" -ne "$HTML_SIGNALS" ]; then
  echo "SYNC FAIL: .md has ${MD_SIGNALS} calibration-reframe signals, .html has ${HTML_SIGNALS}."
  echo "The two sources disagree — one was edited without the other."
  echo "Edit both docs/dns-tool-methodology.md AND docs/dns-tool-methodology.html, or the PDF will republish stale text."
  exit 1
fi
echo "Prose sync OK (${MD_SIGNALS} signals match)"

echo "Generating methodology PDF..."
uv run python -c "
import weasyprint
html = weasyprint.HTML(filename='docs/dns-tool-methodology.html', base_url='docs/')
html.write_pdf('docs/dns-tool-methodology.pdf')
"

cp docs/dns-tool-methodology.pdf static/docs/dns-tool-methodology.pdf
cp docs/dns-tool-methodology.pdf go-server/static/docs/dns-tool-methodology.pdf

SIZE=$(stat -f%z docs/dns-tool-methodology.pdf 2>/dev/null || stat -c%s docs/dns-tool-methodology.pdf 2>/dev/null)
echo "PDF generated: docs/dns-tool-methodology.pdf (${SIZE} bytes)"
echo "Copied to:     static/docs/dns-tool-methodology.pdf"
echo "Copied to:     go-server/static/docs/dns-tool-methodology.pdf"

if [ ! -s docs/dns-tool-methodology.pdf ]; then
  echo "ERROR: docs/dns-tool-methodology.pdf is empty or missing"
  exit 1
fi
if [ ! -s static/docs/dns-tool-methodology.pdf ]; then
  echo "ERROR: static/docs/dns-tool-methodology.pdf is empty or missing"
  exit 1
fi
if [ ! -s go-server/static/docs/dns-tool-methodology.pdf ]; then
  echo "ERROR: go-server/static/docs/dns-tool-methodology.pdf is empty or missing"
  exit 1
fi

echo "Done."
