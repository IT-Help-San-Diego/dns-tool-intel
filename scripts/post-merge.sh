#!/bin/bash
set -e

cd /home/runner/workspace

# Rebuild via build.sh, NOT a bare `go build`: build.sh exports the env this
# environment requires (GOSUMDB=sum.golang.org — the Replit-level GOSUMDB=off
# breaks toolchain-module verification; GOTOOLCHAIN pin; workspace Go caches)
# and injects the git-derived version via ldflags. A bare go build here fails
# with "verifying module: checksum database disabled by GOSUMDB=off" whenever
# go.mod requires a newer toolchain than the Nix-provided go.
if [ -f "go.mod" ]; then
    bash build.sh
fi
