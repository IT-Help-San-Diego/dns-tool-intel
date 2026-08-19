#!/usr/bin/env bash
set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

if [ -f "$HOME/.nix-profile/etc/profile.d/nix.sh" ]; then
  . "$HOME/.nix-profile/etc/profile.d/nix.sh"
fi

# Build with a PATCHED Go toolchain so the shipped binary is free of known Go stdlib
# CVEs. The Nix-provided go is old, which govulncheck flags as code-reachable for
# crypto/tls GO-2026-4340 (handshake encryption level) + GO-2026-4337 (session
# resumption) — hit via SMTP STARTTLS / DANE / DNS-over-TLS probing — and net/url
# GO-2026-4341, plus the later set fixed through go1.26.6 (html/template XSS
# escaper bypasses GO-2026-4980/-4982/-6091, net/http GO-2026-6089/-5026,
# crypto/tls GO-2026-6090/-5856, net/url GO-2026-6218, encoding/xml GO-2026-6088,
# encoding/asn1 GO-2026-5972). GOTOOLCHAIN selects the patched release; GOSUMDB must be a real
# checksum DB (not `off`) or Go refuses to verify/use the toolchain module
# ("checksum database disabled by GOSUMDB=off"). Project modules stay pinned via
# go.sum (`go mod verify` covers them), so the sum DB is consulted only for the
# toolchain itself. On a bump, update this literal + every workflow `go-version:` in
# lockstep (scripts/check-workflow-pin-sync.sh) and reverify:
#   GOSUMDB=sum.golang.org GOTOOLCHAIN=go1.26.X govulncheck ./go-server/...
export GOTOOLCHAIN=go1.26.6
export GOSUMDB=sum.golang.org

# Owl Semaphore derived display assets are PRE-RENDERED and committed. The canonical
# owl art is maintained in the standalone owl-semaphore repository, which is the
# authority; the 540px composites and their responsive derived/ set are committed to
# this repo. They are NO LONGER regenerated on every build. To refresh after pulling
# new composites from the authority repo, run scripts/generate-owl-derived.sh manually.

# Version is DERIVED FROM GIT (scripts/version.sh), never grepped from a tracked
# file. Injecting it via ldflags — exactly like GitCommit/BuildTime below — means
# routine dev ships no longer edit a Version line, which was the single source of
# the chronic every-ship merge conflict on config.go.
VERSION=$(bash "$SCRIPT_DIR/scripts/version.sh")

# Deposit-version gate (UNCONDITIONAL, every build — local and CI). The deposit
# version is declared in docs/metadata files (the manifest in
# scripts/version-files.sh); a sed that matches nothing exits 0, which is why
# {10}/"DNS Tool v10" sat wrong since April. This asserts every version-keyed
# field in a manifested file equals the version the docs/metadata currently
# record — failing the build on any mismatch instead of shipping a stale
# string. It touches only local files, so it needs no opt-in flag. Note: this
# checks DEPOSIT sync (docs + Zenodo metadata), not the git-derived app
# ${VERSION} above — the two are different version classes by design.
if ! bash "$SCRIPT_DIR/scripts/assert-version-strings.sh"; then
  echo "BUILD ABORTED: deposit version strings disagree (see above)." >&2
  echo "Fix the mismatches, or run a generator to re-sync, then rebuild." >&2
  exit 1
fi

GIT_COMMIT=$(git -C "$SCRIPT_DIR" rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_TIME=$(date -u +%Y-%m-%dT%H:%M:%SZ)

LDFLAGS="-s -w \
  -X dnstool/go-server/internal/config.Version=${VERSION} \
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

  # Deploy build is one-shot in an ephemeral container: keep Go caches in /tmp so
  # they are NOT baked into the deployment image. Workspace-relative caches push
  # the image over the 8 GiB limit. The dev-workflow rationale for workspace caches
  # (persistence across restarts, race-avoidance) does not apply to the deploy build.
  export GOCACHE=/tmp/go-build-cache
  export GOMODCACHE=/tmp/go-mod-cache
  export GOTMPDIR=/tmp/go-tmp
  mkdir -p "$GOCACHE" "$GOMODCACHE" "$GOTMPDIR"

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
