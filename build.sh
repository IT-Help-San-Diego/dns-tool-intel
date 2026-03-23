#!/bin/sh
set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

VERSION=$(grep 'Version.*=' "$SCRIPT_DIR/go-server/internal/config/config.go" | head -1 | sed 's/.*"\(.*\)".*/\1/')
GIT_COMMIT=$(git -C "$SCRIPT_DIR" rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_TIME=$(date -u +%Y-%m-%dT%H:%M:%SZ)

LDFLAGS="-s -w \
  -X dnstool/go-server/internal/config.GitCommit=${GIT_COMMIT} \
  -X dnstool/go-server/internal/config.BuildTime=${BUILD_TIME}"

export GOCACHE=/tmp/go-build-cache
export GOMODCACHE=/tmp/go-mod-cache

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

if [ "${REPL_DEPLOYMENT}" = "1" ] || [ "${REPLIT_DEPLOYMENT}" = "1" ] || [ -n "${REPL_DEPLOYMENT_ID}" ]; then
  echo "Deployment build detected — cleaning workspace to reduce disk usage"
  rm -rf .git.backup* .local .cache node_modules .pythonlibs attached_assets \
         .canvas artifacts logs .scannerwork .venv* .codex .drift .gitpanel \
         exports dnstool-intel-staging .agents docs/legacy \
         go-server/internal/*_test.go \
         go-server/internal/**/*_test.go \
         go-server/internal/**/**/*_test.go \
         2>/dev/null || true

  if [ -d .git ]; then
    echo "Removing .git directory (~3.5GB) — not needed at runtime"
    rm -rf .git
  fi

  echo "Deployment cleanup complete"
  du -sh . 2>/dev/null || true
fi

echo "Build complete: dns-tool-server (v${VERSION} ${GIT_COMMIT} ${BUILD_TIME})"
ls -la dns-tool-server
