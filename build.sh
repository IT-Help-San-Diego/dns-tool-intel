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

export GOCACHE=/tmp/go-build-cache
export GOMODCACHE=/tmp/go-mod-cache
export GOTMPDIR=/tmp/go-tmp
# Ensure the Go cache/tmp dirs exist, but NEVER delete them. .replit pins GOCACHE
# under /tmp and this workflow (`bash build.sh && ./dns-tool-server`) re-runs on every
# checkpoint, so any `rm -rf` here RACES concurrent go commands (e.g.
# scripts/quality-gate.sh `go vet`): go lists the cache, decides to auto-trim, and
# trim.txt vanishes underneath it -> "failed to trim cache: ... trim.txt: no such
# file" (and the GOTMPDIR variant "creating work dir: stat ... no such file"). Go's
# build cache is content-addressed, so stale entries can never corrupt a build; wiping
# it only costs build speed and reliability. mkdir -p is idempotent and safe.
mkdir -p /tmp/go-build-cache /tmp/go-tmp

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
