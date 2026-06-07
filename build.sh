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
# Reset the Go cache/tmp dirs at the START of each build (clean build), then leave
# them in place. Do NOT delete them after building: .replit pins GOCACHE/GOTMPDIR
# here, and downstream go commands (e.g. scripts/quality-gate.sh `go vet`) run right
# after this workflow build — a missing dir makes go fail during cache init
# ("failed to trim cache" / "creating work dir"). Leaving the cache also makes the
# post-build gate fast by reusing the warm build cache.
rm -rf /tmp/go-build-cache /tmp/go-tmp 2>/dev/null || true
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
