#!/bin/bash
# require-gnu-sed.sh — resolve a GNU sed binary into $SED, or die.
#
# The release scripts rely on GNU sed's in-place syntax (`sed -i "expr" file`);
# BSD/macOS sed treats the argument after -i as a backup suffix, which silently
# corrupts the run (and litters sedXXXXXX temp files). Linux/Replit system sed
# is GNU. On macOS: `brew install gnu-sed` provides gsed.
#
# Usage (after cd to repo root):  source scripts/lib/require-gnu-sed.sh
# Then use:                       "$SED" -i ...

if sed --version 2>/dev/null | grep -q "GNU sed"; then
  SED="sed"
elif command -v gsed >/dev/null 2>&1; then
  SED="gsed"
else
  echo "ERROR: GNU sed is required (BSD/macOS sed -i is incompatible)." >&2
  echo "  macOS: brew install gnu-sed  (provides gsed)" >&2
  exit 1
fi
