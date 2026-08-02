#!/usr/bin/env bash
# Build on the Mac (or CI), ship the bundle to the EC2 app box, restart, verify.
# Usage: DEPLOY_HOST=ubuntu@dnstool-ec2 bash deploy/deploy-aws.sh
# Fresh box? Run deploy/provision-ec2.sh (as root, once) before the first deploy.
#
# Invariants this script enforces (each one a measured failure mode):
#   1. build.sh --deploy only, NEVER plain `go build`: an un-ldflagged binary
#      stamps literal "dev" into app_version on three production tables and
#      freezes the ?v= asset cache key + service-worker version.
#   2. The version must be tag-derived (X.Y.Z…): a bare-SHA or "dev" version
#      means the checkout has no tags fetched — refuse, don't ship.
#   3. Ship the BUNDLE, not the binary: static/, solver layouts, and
#      CITATION.cff degrade silently when missing. (Templates are compiled
#      into the binary since the embed PR — no longer shipped, cannot be
#      missing.)
#   4. Stage OUTSIDE the live dir, swap stopped, restart after: SRI hashes
#      are boot-computed (changed bytes under a live server are refused by
#      real browsers), and a swap whose staging dirs live INSIDE the rsync
#      destination deletes its own source mid-transfer (reproduced — rsync
#      exit 23, service left stopped, tree corrupted).
#   5. Verify ON THE BOX (localhost /healthz body + --version): the public
#      domain answers from the OLD platform until Route53 flips, so a
#      public-URL check reports READY for a dead box during the exact
#      cutover run this script exists for.
set -euo pipefail

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
DEPLOY_HOST="${DEPLOY_HOST:?set DEPLOY_HOST=user@host}"
DEPLOY_PATH="${DEPLOY_PATH:-/opt/dnstool}"
STAGE_PATH="${STAGE_PATH:-${DEPLOY_PATH}-stage}"   # OUTSIDE the live dir (invariant 4)
APP_PORT="${APP_PORT:-5000}"

cd "$REPO_DIR"

# --- 2: tag-derived version or refuse -------------------------------------
VERSION="$(bash scripts/version.sh)"
case "$VERSION" in
  *.*.*) : ;;
  *)
    echo "REFUSING TO DEPLOY: version '$VERSION' is not tag-derived." >&2
    echo "Run from a full clone with tags: git fetch --tags" >&2
    exit 1
    ;;
esac

# --- 1: canonical build, cross-compiled for Graviton ----------------------
echo "Building v${VERSION} for linux/arm64…"
GOOS=linux GOARCH=arm64 bash build.sh --deploy

# --- 3: stage the bundle (clean slate; -R creates the full relative tree) --
# Clear the stage's CONTENTS, never `rm -rf` the directory itself: removing a
# directory ENTRY requires write on its parent, and the parent (/opt) is
# root-owned — so `rm -rf $STAGE_PATH` fails for the non-root deploy user on
# every properly provisioned box (measured on the first real deploy,
# 2026-08-02; provision-ec2.sh creates the dir deploy-user-owned, which
# grants control of the contents, not the entry). `find -mindepth 1 -delete`
# empties it as the owner, dotfiles included. mkdir -p still covers a box
# where provisioning was skipped — and fails loudly there if /opt is not
# writable, which is the correct pointer to run provision-ec2.sh first.
echo "Staging bundle at ${DEPLOY_HOST}:${STAGE_PATH}…"
ssh "$DEPLOY_HOST" "mkdir -p '${STAGE_PATH}' && find '${STAGE_PATH}' -mindepth 1 -delete"
rsync -azR \
  dns-tool-server \
  CITATION.cff \
  static \
  go-server/tools/topology-solver/output \
  "${DEPLOY_HOST}:${STAGE_PATH}/"

# --- 4: swap stopped, always restart --------------------------------------
# No `set -e` around the swap: whatever happens, the service is started
# again (old tree on rsync failure, new tree on success) and the rsync exit
# code still fails the deploy. --exclude=/logs protects the writable dir
# (absent from the stage) from --delete.
echo "Swapping ${DEPLOY_PATH} and restarting…"
ssh "$DEPLOY_HOST" "set -u
  sudo systemctl stop dnstool
  rsync -a --delete --exclude=/logs '${STAGE_PATH}/' '${DEPLOY_PATH}/'
  rc=\$?
  chmod +x '${DEPLOY_PATH}/dns-tool-server' 2>/dev/null || true
  sudo systemctl start dnstool
  exit \$rc
"

# --- 5: verify on the box — version first, then ready body ----------------
echo "Verifying deployed binary version…"
DEPLOYED_VERSION="$(ssh "$DEPLOY_HOST" "cd '${DEPLOY_PATH}' && ./dns-tool-server --version" || true)"
if ! printf '%s' "$DEPLOYED_VERSION" | grep -qF "$VERSION"; then
  echo "DEPLOY VERIFICATION FAILED: box reports '$DEPLOYED_VERSION', expected v${VERSION}." >&2
  exit 1
fi
echo "Version confirmed: v${VERSION}"

echo "Waiting for ready /healthz on the box (body match, not status code)…"
body=""
for i in $(seq 1 30); do
  body="$(ssh "$DEPLOY_HOST" "curl -fsS --max-time 5 http://127.0.0.1:${APP_PORT}/healthz" 2>/dev/null || true)"
  if printf '%s' "$body" | grep -q '"status":"ok"'; then
    echo "READY: $body"
    # Optional extra: public-URL check, meaningful only AFTER the DNS flip.
    if [ -n "${HEALTH_URL:-}" ]; then
      pub="$(curl -fsS --max-time 5 "$HEALTH_URL" 2>/dev/null || true)"
      echo "Public check ${HEALTH_URL}: ${pub:-<no answer>} (authoritative only post-flip)"
    fi
    exit 0
  fi
  sleep 2
done
echo "DEPLOY VERIFICATION FAILED: box-local /healthz never reported status ok." >&2
echo "Last body: ${body:-<empty>}" >&2
echo "Check: ssh $DEPLOY_HOST journalctl -u dnstool -n 50" >&2
exit 1
