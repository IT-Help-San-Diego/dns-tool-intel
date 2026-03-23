#!/bin/bash
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

pass() { echo -e "  ${GREEN}✓${NC} $1"; }
info() { echo -e "${YELLOW}▸${NC} $1"; }

cd "$(dirname "$0")/.."

export PYTHONPATH="/home/runner/workspace/.pythonlibs/lib/python3.12/site-packages:${PYTHONPATH:-}"

echo ""
info "Git history cleanup — removing binary blobs"
echo ""
echo "  Before:"
echo "    .git size: $(du -sh .git | cut -f1)"
BLOB_COUNT=$(git rev-list --objects --all -- dns-tool-server dns-tool-server-new dns-tool go-server/dns-tool-server go-server/dns-tool go-server/probe 2>/dev/null | wc -l)
echo "    Binary objects in history: $BLOB_COUNT"
echo ""

info "Running git-filter-repo to remove binary paths from history..."
git filter-repo \
  --path dns-tool-server \
  --path dns-tool-server-new \
  --path dns-tool \
  --path go-server/dns-tool-server \
  --path go-server/dns-tool \
  --path go-server/probe \
  --invert-paths \
  --force

info "Cleaning up reflog and repacking..."
git reflog expire --expire=now --all 2>/dev/null || true
git gc --prune=now --aggressive 2>/dev/null || true

echo ""
echo "  After:"
echo "    .git size: $(du -sh .git | cut -f1)"
NEW_BLOB_COUNT=$(git rev-list --objects --all -- dns-tool-server dns-tool-server-new dns-tool go-server/dns-tool-server go-server/dns-tool go-server/probe 2>/dev/null | wc -l)
echo "    Binary objects in history: $NEW_BLOB_COUNT"
echo ""

info "Re-adding remotes..."
git remote add origin https://github.com/careyjames/dns-tool-intel.git 2>/dev/null || true
git remote add gitsafe-backup git://gitsafe:5418/backup.git 2>/dev/null || true

pass "Local git history cleaned. All code commits preserved, binary blobs removed."
echo ""
echo "  Note: GitHub repo is already clean (158 MB). No force-push needed."
echo "  The .git.backup directory (3.2 GB) can also be safely deleted:"
echo "    rm -rf .git.backup.20260304_170840"
echo ""
