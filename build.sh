#!/bin/sh
# cache-bust: 2026-04-07T21:50Z — cleanup-first to reduce peak disk usage
set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

VERSION=$(grep 'Version.*=' "$SCRIPT_DIR/go-server/internal/config/config.go" | head -1 | sed 's/.*"\(.*\)".*/\1/')
GIT_COMMIT=$(git -C "$SCRIPT_DIR" rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_TIME=$(date -u +%Y-%m-%dT%H:%M:%SZ)

LDFLAGS="-s -w \
  -X dnstool/go-server/internal/config.GitCommit=${GIT_COMMIT} \
  -X dnstool/go-server/internal/config.BuildTime=${BUILD_TIME}"

if [ "$1" = "--deploy" ]; then
  echo "Deployment build — cleaning non-runtime files BEFORE compile"
  echo "Before cleanup:"
  du -sh . 2>/dev/null || true
  df -h . 2>/dev/null || true

  rm -rf .git.backup* 2>/dev/null || true

  rm -rf .local .cache .scannerwork .codex .drift .gitpanel \
         exports dnstool-intel-staging .intel \
         attached_assets .canvas artifacts \
         docs/legacy docs/EVOLUTION_APPEND_*.md docs/dns-tool-methodology.pdf \
         EVOLUTION.md PROJECT_CONTEXT.md \
         sonar-project.properties \
         node_modules .pythonlibs \
         src stubs tests dns-eval security \
         logs instance .agents \
         .config/chromium .config/configstore .config/pulse \
         2>/dev/null || true

  find go-server/internal -name '*_test.go' -delete 2>/dev/null || true
  find . -maxdepth 1 -name '*.md' ! -name 'replit.md' -delete 2>/dev/null || true

  echo "After cleanup:"
  du -sh . 2>/dev/null || true
  df -h . 2>/dev/null || true
  echo "Pre-build cleanup complete"
fi

export GOCACHE="$SCRIPT_DIR/.go-build-cache"
export GOMODCACHE="$SCRIPT_DIR/.go-mod-cache"

echo "Building dns-tool-server..."
cd "$SCRIPT_DIR/go-server"
CGO_ENABLED=0 GONOSUMCHECK=1 GIT_DIR=/dev/null go build \
  -buildvcs=false \
  -trimpath \
  -ldflags "$LDFLAGS" \
  -tags netgo \
  -o "$SCRIPT_DIR/dns-tool-server-new" \
  ./cmd/server/
cd "$SCRIPT_DIR"
mv dns-tool-server-new dns-tool-server

if [ "$1" = "--deploy" ]; then
  rm -rf .go-build-cache .go-mod-cache 2>/dev/null || true
  echo "Final size:"
  du -sh . 2>/dev/null || true
fi

echo "Build complete: dns-tool-server (v${VERSION} ${GIT_COMMIT} ${BUILD_TIME})"
ls -la dns-tool-server
