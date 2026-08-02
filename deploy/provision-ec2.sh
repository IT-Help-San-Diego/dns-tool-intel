#!/usr/bin/env bash
# One-shot provisioning for a fresh EC2 app box. Run as root, once, before the
# first deploy. Idempotent — safe to re-run. Everything deploy-aws.sh and
# dnstool.service assume exists is created HERE (the adversarial review found
# four distinct fresh-box failures when these were left implicit: no service
# user, no /etc/dnstool/env, no writable /opt/dnstool, no NOPASSWD sudo for
# the deploy user's systemctl calls).
#
# Usage (as root on the box): DEPLOY_USER=ubuntu bash provision-ec2.sh
set -euo pipefail

DEPLOY_PATH="${DEPLOY_PATH:-/opt/dnstool}"
STAGE_PATH="${STAGE_PATH:-${DEPLOY_PATH}-stage}"
DEPLOY_USER="${DEPLOY_USER:-ubuntu}"
UNIT_SRC="$(cd "$(dirname "$0")" && pwd)/dnstool.service"

echo "== provision: service user =="
id dnstool >/dev/null 2>&1 || useradd --system --home-dir /nonexistent --shell /usr/sbin/nologin dnstool
echo "  CHECK: $(id dnstool)"

echo "== provision: directories =="
# Live tree + stage owned by the deploy user (rsync writes them); logs/ owned
# by the service user (the ONLY path the unit's ProtectSystem=strict leaves
# writable, and systemd refuses to start if a ReadWritePaths entry is absent).
# NOTE the ownership contract with deploy-aws.sh: these dirs live under
# root-owned /opt, so the deploy user can manage their CONTENTS but can never
# remove the directory entries themselves — deploy-aws.sh therefore CLEARS
# the stage (find -mindepth 1 -delete), it must never `rm -rf` it.
install -d -o "$DEPLOY_USER" -g "$DEPLOY_USER" "$DEPLOY_PATH" "$STAGE_PATH"
install -d -o dnstool -g dnstool "$DEPLOY_PATH/logs"
echo "  CHECK: $(ls -ld "$DEPLOY_PATH" "$DEPLOY_PATH/logs" "$STAGE_PATH")"

echo "== provision: /etc/dnstool/env =="
install -d -m 750 /etc/dnstool
if [ ! -f /etc/dnstool/env ]; then
  cat > /etc/dnstool/env <<'EOF'
# DNS Tool environment — read by systemd as root; keep mode 600.
# FILL THE PLACEHOLDERS before first start.
DATABASE_URL=CHANGE_ME_RDS_CONNECTION_STRING
SESSION_SECRET=CHANGE_ME
PORT=5000
# The cloud→local lever: without it the public site impersonates a local
# build (no privacy banner, "local" badge, /history flipper, Wayback OFF).
CLOUD_DEPLOYMENT=1
# BASE_URL defaults to https://dnstool.it-help.tech when unset.
# TRUSTED_PROXIES stays unset until phase 2 (CloudFront/ALB).
EOF
  echo "  wrote template — FILL THE PLACEHOLDERS"
else
  echo "  exists, left untouched"
fi
chmod 600 /etc/dnstool/env
echo "  CHECK: $(ls -l /etc/dnstool/env)"

echo "== provision: sudoers for the deploy user's systemctl calls =="
cat > /etc/sudoers.d/dnstool-deploy <<EOF
$DEPLOY_USER ALL=(root) NOPASSWD: /usr/bin/systemctl start dnstool, /usr/bin/systemctl stop dnstool, /usr/bin/systemctl restart dnstool
EOF
chmod 440 /etc/sudoers.d/dnstool-deploy
visudo -cf /etc/sudoers.d/dnstool-deploy
echo "  CHECK: visudo validated"

echo "== provision: systemd unit (single source: deploy/dnstool.service) =="
install -m 644 "$UNIT_SRC" /etc/systemd/system/dnstool.service
systemctl daemon-reload
systemctl enable dnstool
echo "  CHECK: $(systemctl is-enabled dnstool)"

echo "== provision complete =="
echo "Next: fill /etc/dnstool/env, then run deploy/deploy-aws.sh from the Mac."
