#!/bin/bash
# ╔══════════════════════════════════════════════════════════════════╗
# ║  DEPRECATED — DO NOT USE                                        ║
# ║                                                                  ║
# ║  git-sync.sh is obsolete. It requires Python3 (not installed),   ║
# ║  pushes directly to main (violates branch protection), and       ║
# ║  uses the GitHub Trees/Commits API instead of git push.          ║
# ║                                                                  ║
# ║  Replacement: bash scripts/git-push.sh                           ║
# ║  Workflow:    bash scripts/dev-bump.sh X.Y.Z                     ║
# ║               bash scripts/git-push.sh                           ║
# ╚══════════════════════════════════════════════════════════════════╝

echo ""
echo "ERROR: git-sync.sh is DEPRECATED and will not run."
echo ""
echo "Use the replacement script:"
echo "  bash scripts/git-push.sh"
echo ""
echo "Full workflow:"
echo "  bash scripts/dev-bump.sh X.Y.Z"
echo "  bash scripts/git-push.sh"
echo ""
exit 1
