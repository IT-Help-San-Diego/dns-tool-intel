#!/bin/sh
set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

VERSION=$(grep 'Version.*=' "$SCRIPT_DIR/go-server/internal/config/config.go" | head -1 | sed 's/.*"\(.*\)".*/\1/')

GIT_COMMIT=$(git -C "$SCRIPT_DIR" rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_TIME=$(date -u +%Y-%m-%dT%H:%M:%SZ)

LDFLAGS="-s -w \
  -X dnstool/go-server/internal/config.GitCommit=${GIT_COMMIT} \
  -X dnstool/go-server/internal/config.BuildTime=${BUILD_TIME}"

if [ "$1" = "--deploy" ]; then
  echo "Deployment build — v${VERSION}"
  echo "Before cleanup:"
  du -sh . 2>/dev/null || true

  echo "Compiling dns-tool-server for deployment..."
  export GOCACHE=/tmp/go-build-cache
  export GOMODCACHE=/tmp/go-mod-cache
  cd "$SCRIPT_DIR/go-server"
  CGO_ENABLED=0 GONOSUMCHECK=1 GIT_DIR=/dev/null go build \
    -buildvcs=false \
    -trimpath \
    -ldflags "$LDFLAGS" \
    -tags netgo \
    -o "$SCRIPT_DIR/dns-tool-server" \
    ./cmd/server/
  cd "$SCRIPT_DIR"
  rm -rf /tmp/go-build-cache /tmp/go-mod-cache 2>/dev/null || true

  echo "Binary built:"
  ls -la "$SCRIPT_DIR/dns-tool-server"
  file "$SCRIPT_DIR/dns-tool-server"

  echo "Cleaning non-runtime files..."
  rm -rf .git.backup* 2>/dev/null || true
  rm -rf .scannerwork .codex .drift .gitpanel \
         exports dnstool-intel-staging .intel \
         attached_assets .canvas artifacts \
         node_modules .pythonlibs \
         src stubs tests dns-eval security \
         logs instance .agents \
         .go-build-cache .go-mod-cache \
         EVOLUTION.md PROJECT_CONTEXT.md \
         static/references \
         go-server/cmd go-server/tools go-server/exports go-server/scripts \
         go.mod go.sum \
         2>/dev/null || true
  rm -rf docs 2>/dev/null || true
  rm -rf .cache/uv .cache/pip .cache/go-build .cache/node \
         .config/chromium .config/configstore .config/pulse \
         2>/dev/null || true

  find go-server/internal -name '*_test.go' -delete 2>/dev/null || true
  find . -maxdepth 1 -name '*.md' ! -name 'replit.md' -delete 2>/dev/null || true

  echo "After cleanup:"
  du -sh . 2>/dev/null || true
  echo "Deployment build complete — v${VERSION} ${GIT_COMMIT} ${BUILD_TIME}"
  exit 0
fi

export GOCACHE=/tmp/go-build-cache
export GOMODCACHE=/tmp/go-mod-cache

echo "Building dns-tool-server..."
cd "$SCRIPT_DIR/go-server"
CGO_ENABLED=0 GONOSUMCHECK=1 GIT_DIR=/dev/null go build \
  -buildvcs=false \
  -trimpath \
  -ldflags "$LDFLAGS" \
  -tags netgo \
  -o /tmp/dns-tool-new \
  ./cmd/server/
cd "$SCRIPT_DIR"
mv /tmp/dns-tool-new dns-tool-server-new
mv dns-tool-server-new dns-tool-server

rm -rf /tmp/go-build-cache /tmp/go-mod-cache 2>/dev/null || true

echo "Build complete: dns-tool-server (v${VERSION} ${GIT_COMMIT} ${BUILD_TIME})"
ls -la dns-tool-server
