#!/bin/bash
# Generate the philosophical foundations PDF from the HTML source using WeasyPrint.
# Usage: bash scripts/generate-foundations-pdf.sh [VERSION]
#
# If VERSION is provided, updates the version in both .html and .md before
# generating the PDF. If omitted, generates from current content.
#
# Prerequisites: weasyprint (listed in pyproject.toml)
# Logo asset: static/images/owl-signature.png (Owl of Athena — dark background, premium version)
#
# This MUST be run after every edit to docs/philosophical-foundations.html

set -euo pipefail
cd "$(dirname "$0")/.."

VERSION="${1:-}"

if [ -n "$VERSION" ]; then
  source scripts/lib/require-gnu-sed.sh
  echo "Updating foundations version to ${VERSION}..."

  "$SED" -i -E "s/Version<\/span>\&ensp;[0-9]+\.[0-9]+\.[0-9]+/Version<\/span>\&ensp;${VERSION}/" docs/philosophical-foundations.html
  "$SED" -i -E "s/DNS Tool v[0-9]+\.[0-9]+\.[0-9]+/DNS Tool v${VERSION}/" docs/philosophical-foundations.html
  "$SED" -i -E "s/Version [0-9]+\.[0-9]+\.[0-9]+/Version ${VERSION}/" docs/philosophical-foundations.md
  "$SED" -i -E "s/DNS Tool v[0-9]+\.[0-9]+\.[0-9]+/DNS Tool v${VERSION}/" docs/philosophical-foundations.md

  echo "Version updated in .html and .md"

  # Post-write assertion: the foundations .md/.html are deposit documents in
  # the shared manifest (scripts/version-files.sh). Each sed above has its own
  # pattern and a sed that matches nothing exits 0 — so verify from the files,
  # not the patterns. Fail if any version key in these two files disagrees.
  echo "Verifying version strings..."
  FAILED=0
  for f in docs/philosophical-foundations.md docs/philosophical-foundations.html; do
    if [ -f "$f" ]; then
      MISMATCH=$(grep -v '^cff-version:' "$f" | sed -nE \
        -e 's/.*"version"[[:space:]]*:[[:space:]]*"([^"]*)".*/\1/p' \
        -e 's/^Version[[:space:]]+([^[:space:]]+).*/\1/p' \
        -e 's/.*Version<\/span>&ensp;([^&<]*).*/\1/p' \
        -e 's/.*DNS Tool v([^[:space:]]+).*/\1/p' \
        | sed -E 's/["{},]//g' | grep -v "^${VERSION}$" | head -1 || true)
      if [ -n "$MISMATCH" ]; then
        echo "VERSION MISMATCH in $f: found $MISMATCH, expected $VERSION"
        FAILED=1
      fi
    fi
  done
  if [ "$FAILED" -eq 1 ]; then
    echo "FAIL: version strings disagree. Fix the mismatches above and re-run."
    exit 1
  fi
  echo "Version strings verified"
fi

echo "Generating philosophical foundations PDF..."
uv run python -c "
import weasyprint
html = weasyprint.HTML(filename='docs/philosophical-foundations.html', base_url='docs/')
html.write_pdf('docs/philosophical-foundations.pdf')
"

cp docs/philosophical-foundations.pdf static/docs/philosophical-foundations.pdf
cp docs/philosophical-foundations.pdf go-server/static/docs/philosophical-foundations.pdf

SIZE=$(stat -f%z docs/philosophical-foundations.pdf 2>/dev/null || stat -c%s docs/philosophical-foundations.pdf 2>/dev/null)
echo "PDF generated: docs/philosophical-foundations.pdf (${SIZE} bytes)"
echo "Copied to:     static/docs/philosophical-foundations.pdf"
echo "Copied to:     go-server/static/docs/philosophical-foundations.pdf"

if [ ! -s docs/philosophical-foundations.pdf ]; then
  echo "ERROR: docs/philosophical-foundations.pdf is empty or missing"
  exit 1
fi
if [ ! -s static/docs/philosophical-foundations.pdf ]; then
  echo "ERROR: static/docs/philosophical-foundations.pdf is empty or missing"
  exit 1
fi
if [ ! -s go-server/static/docs/philosophical-foundations.pdf ]; then
  echo "ERROR: go-server/static/docs/philosophical-foundations.pdf is empty or missing"
  exit 1
fi

echo "Done."
