#!/usr/bin/env bash
set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

if [ -f "$HOME/.nix-profile/etc/profile.d/nix.sh" ]; then
  . "$HOME/.nix-profile/etc/profile.d/nix.sh"
fi

CONVERT=$(command -v magick 2>/dev/null || command -v convert 2>/dev/null || true)
CWEBP=$(command -v cwebp 2>/dev/null || true)

if [ -n "$CONVERT" ] && [ -n "$CWEBP" ]; then
  echo "Generating Owl Semaphore derived assets..."
  bash "$SCRIPT_DIR/scripts/generate-owl-derived.sh"
else
  echo "SKIP derived asset generation (ImageMagick/cwebp not found)"
  echo "  convert: ${CONVERT:-(not found)}"
  echo "  cwebp:   ${CWEBP:-(not found)}"
fi

VERSION=$(grep 'Version.*=' "$SCRIPT_DIR/go-server/internal/config/config.go" | head -1 | sed 's/.*"\(.*\)".*/\1/')

GIT_COMMIT=$(git -C "$SCRIPT_DIR" rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_TIME=$(date -u +%Y-%m-%dT%H:%M:%SZ)

LDFLAGS="-s -w \
  -X dnstool/go-server/internal/config.GitCommit=${GIT_COMMIT} \
  -X dnstool/go-server/internal/config.BuildTime=${BUILD_TIME}"

export GOCACHE=/tmp/go-build-cache
export GOMODCACHE=/tmp/go-mod-cache

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
  rm -rf /tmp/go-build-cache /tmp/go-mod-cache 2>/dev/null || true

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
  -o /tmp/dns-tool-new \
  ./go-server/cmd/server/
mv /tmp/dns-tool-new dns-tool-server-new
mv dns-tool-server-new dns-tool-server

rm -rf /tmp/go-build-cache /tmp/go-mod-cache 2>/dev/null || true

echo "Build complete: dns-tool-server (v${VERSION} ${GIT_COMMIT} ${BUILD_TIME})"
ls -la dns-tool-server
