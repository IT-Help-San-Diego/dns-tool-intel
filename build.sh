#!/usr/bin/env bash
set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

if [ -f "$HOME/.nix-profile/etc/profile.d/nix.sh" ]; then
  . "$HOME/.nix-profile/etc/profile.d/nix.sh"
fi

CONVERT=$(command -v magick 2>/dev/null || command -v convert 2>/dev/null || true)
CWEBP=$(command -v cwebp 2>/dev/null || true)

if [ -n "$CONVERT" ] && [ -n "$CWEBP" ]; then
  bash "$SCRIPT_DIR/scripts/generate-owl-derived.sh"
else
  echo "SKIP derived asset generation (ImageMagick/cwebp not found)"
fi

VERSION=$(grep 'Version.*=' "$SCRIPT_DIR/go-server/internal/config/config.go" | head -1 | sed 's/.*"\(.*\)".*/\1/')

GIT_COMMIT=$(git -C "$SCRIPT_DIR" rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_TIME=$(date -u +%Y-%m-%dT%H:%M:%SZ)

LDFLAGS="-s -w \
  -X dnstool/go-server/internal/config.GitCommit=${GIT_COMMIT} \
  -X dnstool/go-server/internal/config.BuildTime=${BUILD_TIME}"

# Go caches live in the WORKSPACE (persistent, gitignored), NOT /tmp. /tmp is subject
# to OS pruning AND, previously, to this script's own `rm -rf`, which raced concurrent
# go commands (e.g. scripts/quality-gate.sh `go vet`) and produced
# "failed to trim cache: ... trim.txt: no such file" / "creating work dir: stat ...".
# Workspace-relative paths survive both OS /tmp cleanup and the workflow restart that
# fires on every checkpoint (`bash build.sh && ./dns-tool-server`). NEVER delete these
# dirs: Go's cache is content-addressed, so stale entries can't corrupt a build.
# mkdir -p is idempotent and safe. Keep these in lockstep with .replit [userenv.shared].
export GOCACHE="$SCRIPT_DIR/.go-build-cache"
export GOMODCACHE="$SCRIPT_DIR/.go-mod-cache"
export GOTMPDIR="$SCRIPT_DIR/.go-tmp"
mkdir -p "$GOCACHE" "$GOMODCACHE" "$GOTMPDIR"

if [ "$1" = "--deploy" ]; then
  echo "Deployment build — v${VERSION}"

  echo "Compiling dns-tool-server for deployment..."
  cd "$SCRIPT_DIR"
  CGO_ENABLED=0 GONOSUMCHECK=1 go build \
    -buildvcs=false \
    -trimpath \
    -ldflags "$LDFLAGS" \
    -tags netgo \
    -o "$SCRIPT_DIR/dns-tool-server" \
    ./go-server/cmd/server/

  echo "Binary built:"
  ls -la "$SCRIPT_DIR/dns-tool-server"
  file "$SCRIPT_DIR/dns-tool-server"

  echo "Deployment build complete — v${VERSION} ${GIT_COMMIT} ${BUILD_TIME}"
  exit 0
fi

echo "Building dns-tool-server..."
cd "$SCRIPT_DIR"
CGO_ENABLED=0 GONOSUMCHECK=1 go build \
  -buildvcs=false \
  -trimpath \
  -ldflags "$LDFLAGS" \
  -tags netgo \
  -o "$SCRIPT_DIR/dns-tool-server-new" \
  ./go-server/cmd/server/
mv "$SCRIPT_DIR/dns-tool-server-new" "$SCRIPT_DIR/dns-tool-server"

echo "Build complete: dns-tool-server (v${VERSION} ${GIT_COMMIT} ${BUILD_TIME})"
ls -la dns-tool-server
