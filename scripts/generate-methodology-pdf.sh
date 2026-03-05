#!/bin/bash
# Generate the methodology PDF from the HTML source using WeasyPrint.
# Usage: bash scripts/generate-methodology-pdf.sh
#
# Prerequisites: weasyprint (listed in pyproject.toml)
# Logo asset: static/images/owl-of-athena.png (Owl of Athena)
#
# This MUST be run after every version bump that touches
# docs/dns-tool-methodology.html or docs/dns-tool-methodology.md

set -euo pipefail
cd "$(dirname "$0")/.."

echo "Generating methodology PDF..."
python -c "
import weasyprint
html = weasyprint.HTML(filename='docs/dns-tool-methodology.html', base_url='docs/')
html.write_pdf('docs/dns-tool-methodology.pdf')
"

cp docs/dns-tool-methodology.pdf static/docs/dns-tool-methodology.pdf

SIZE=$(stat -f%z docs/dns-tool-methodology.pdf 2>/dev/null || stat -c%s docs/dns-tool-methodology.pdf 2>/dev/null)
echo "PDF generated: docs/dns-tool-methodology.pdf (${SIZE} bytes)"
echo "Copied to:     static/docs/dns-tool-methodology.pdf"
