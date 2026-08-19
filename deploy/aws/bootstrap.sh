#!/usr/bin/env bash
# dns-tool AWS bootstrap — phase 1 (direct-to-EC2 cutover)
# Architecture: EC2 app (t4g.medium, public site) + RDS Postgres (db.t4g.small, PRIVATE, PITR)
# Region: us-west-2. Every step ends with a measured check. No "should work".
set -euo pipefail

REGION="us-west-2"
APP_INSTANCE_TYPE="t4g.medium"
RDS_INSTANCE_CLASS="db.t4g.small"
DB_NAME="neondb"
DB_USER="dnstool"
# (DB password injected from env at run time — never hardcoded)
BACKUP_BUCKET="dnstool-backups-objectlock"   # NEW bucket; Object Lock only settable at creation

echo "== dns-tool AWS bootstrap =="
echo "Region: $REGION"

# ---------------------------------------------------------------------------
# STEP 1 — Backup bucket FIRST (so it exists before the DB has anything to lose)
# Object Lock is ONLY settable at bucket creation. None of the 5 existing
# buckets have it (verified 2026-08-01). This bucket: PutObject-only writer.
# ---------------------------------------------------------------------------
echo "== STEP 1: create Object-Locked backup bucket =="
aws s3api create-bucket \
  --bucket "$BACKUP_BUCKET" \
  --region "$REGION" \
  --create-bucket-configuration LocationConstraint="$REGION" \
  --object-lock-enabled-for-bucket

aws s3api put-object-lock-configuration \
  --bucket "$BACKUP_BUCKET" \
  --object-lock-configuration 'ObjectLockEnabled="Enabled",Rule={DefaultRetention={Mode=COMPLIANCE,Days=30}}'

echo "  CHECK: object-lock config ="
aws s3api get-object-lock-configuration --bucket "$BACKUP_BUCKET" --query 'ObjectLockConfiguration' --output json

# ---------------------------------------------------------------------------
# STEP 2 — RDS Postgres, PRIVATE (no public endpoint), PITR enabled.
# PITR is the PRIMARY recovery path (it limited the 2026-08-01 loss to 9 rows).
# ---------------------------------------------------------------------------
echo "== STEP 2: RDS $RDS_INSTANCE_CLASS, private, PITR =="
# (Security group + subnet group assumed created/looked-up; placeholders below)
aws rds create-db-instance \
  --db-instance-identifier dnstool-pg \
  --db-instance-class "$RDS_INSTANCE_CLASS" \
  --engine postgres \
  --engine-version "18" \
  --master-username "$DB_USER" \
  --master-user-password "$DB_PASSWORD" \
  --allocated-storage 20 \
  --storage-type gp3 \
  --no-publicly-accessible \
  --backup-retention-period 7 \
  --preferred-backup-window "10:00-11:00" \
  --region "$REGION" \
  --tags Key=Project,Value=dns-tool Key=Role,Value=database

echo "  waiting for RDS available…"
aws rds wait db-instance-available --db-instance-identifier dnstool-pg --region "$REGION"
DB_ENDPOINT=$(aws rds describe-db-instances --db-instance-identifier dnstool-pg --region "$REGION" --query 'DBInstances[0].Endpoint.Address' --output text)
echo "  CHECK: RDS endpoint = $DB_ENDPOINT (private)"

# ---------------------------------------------------------------------------
# STEP 3 — Restore the sealed July 26 dump (--no-owner --no-privileges).
# Goose adoption probe runs on first binary boot: stamp_through=18 then applied=1.
# ---------------------------------------------------------------------------
echo "== STEP 3: restore July 26 dump =="
echo "  (run from a host that can reach the private RDS — the EC2 box or via SSH tunnel)"
echo "  pg_restore -h $DB_ENDPOINT -U $DB_USER -d $DB_NAME --no-owner --no-privileges -j4 neondb.dump"
echo "  CHECK: 37 tables present; both score tables VARCHAR(20) pre-019"

# ---------------------------------------------------------------------------
# STEP 4 — ⚠ NUMBERED STEP: reseat sequences BEFORE any traffic.
# The dump's sequences sit at 18093 / 286169; the 6-day tail needs 18094-18107.
# These literals are production's last_value, measured on Replit before deletion.
# NOT re-derivable. Carry as literals.
# ---------------------------------------------------------------------------
echo "== STEP 4: reseat sequences (MANDATORY, before first scan) =="
echo "  psql -h $DB_ENDPOINT -U $DB_USER -d $DB_NAME -c \\"
echo "    \"SELECT setval('domain_analyses_id_seq',      18116, true); \\"
echo "     SELECT setval('scan_phase_telemetry_id_seq', 286836, true);\""
echo "  Reserves 18094–18107 for the tail; 18108–18116 = permanent gap (the 9 lost rows)."
echo "  CHECK: SELECT last_value FROM domain_analyses_id_seq;  -- expect 18116"
echo "         SELECT last_value FROM scan_phase_telemetry_id_seq;  -- expect 286836"

# ---------------------------------------------------------------------------
# STEP 5 — EC2 app box, 24/7 (public site, no idle-stop).
# SG: port 22 from Carey's IP only; 80/443 from world (it's a public site).
# Instance profile: s3:PutObject on the backup bucket, NO s3:DeleteObject.
# ---------------------------------------------------------------------------
echo "== STEP 5: EC2 app box (t4g.medium, 24/7) + PutObject-only instance profile =="
echo "  SG inbound: 22 from Carey-IP/32, 80+443 from 0.0.0.0/0"
echo "  Instance profile policy: s3:PutObject on $BACKUP_BUCKET only (no DeleteObject)"
echo "  CHECK: instance profile attached; aws sts get-caller-identity from box"

# ---------------------------------------------------------------------------
# STEP 5.5 — PRE-CUTOVER code changes (Claude Code's PR `aws/pre-cutover-levers`,
# lands BEFORE first boot). These are PHASE 1, not phase 2:
#   - re-key IsCloudDeployment (CLOUD_DEPLOYMENT OR'd with old var — NOT strip).
#     Without it step 7's first boot runs prod as a LOCAL build: no privacy
#     banner, "local" nav badge, /history flipper false "never leaves your
#     machine" claim, and Wayback archival silently OFF.
#   - restore HSTS (middleware.go:161 — without it the header vanishes at step 9
#     the moment Replit's edge stops fronting the site).
#   - health endpoint returns 503 for starting/degraded/crash-loop states.
# (trusted-proxies is genuinely phase 2 — localhost-only is correct for direct serving.)
# ---------------------------------------------------------------------------
echo "== STEP 5.5: land Claude Code's aws/pre-cutover-levers PR BEFORE first boot =="
echo "  re-key IsCloudDeployment, restore HSTS, health-503 states. trusted-proxies = phase 2."
echo "  CHECK: PR merged to main; binary built from a checkout that includes it"

# ---------------------------------------------------------------------------
# STEP 6 — Provision the box via deploy/provision-ec2.sh (merged #262, on main),
# install Go 1.26.6 explicitly, build via build.sh --deploy.
# provision-ec2.sh (root, once) creates: service user, /opt/dnstool{,-stage,/logs},
# /etc/dnstool/env template (CLOUD_DEPLOYMENT=1 preset), sudoers rule, installs+
# enables deploy/dnstool.service. Then deploys ship via deploy/deploy-aws.sh
# (stages at /opt/dnstool-stage, verifies --version + /healthz body "status":"ok").
# ---------------------------------------------------------------------------
echo "== STEP 6: deploy/provision-ec2.sh + Go 1.26.6 + build.sh --deploy =="
GO_VERSION="1.26.6"
echo "  Provision the fresh box (root, once) — from the merged #262 script on main:"
echo "    sudo bash /opt/dnstool/deploy/provision-ec2.sh"
echo "    # creates service user, /opt/dnstool{,-stage,/logs}, /etc/dnstool/env (CLOUD_DEPLOYMENT=1),"
echo "    # sudoers, installs+enables deploy/dnstool.service (single source for the unit)"
echo "  Install Go $GO_VERSION explicitly (arm64; no toolchain auto-download):"
echo "    curl -fsSLo /tmp/go.tgz https://go.dev/dl/go${GO_VERSION}.linux-arm64.tar.gz"
echo "    rm -rf /usr/local/go && tar -C /usr/local -xzf /tmp/go.tgz"
echo "    /usr/local/go/bin/go version   # CHECK: go version go${GO_VERSION} linux/arm64"
echo "  Fill /etc/dnstool/env: DATABASE_URL=<rds private>, SESSION_SECRET=<gen>, PORT=443 (CLOUD_DEPLOYMENT=1 preset)"
echo "  Build + deploy from the full git checkout with tags (NEVER plain go build):"
echo "    cd /opt/dnstool && sudo -u dnstool bash deploy/deploy-aws.sh"
echo "    # cross-compiles GOOS=linux GOARCH=arm64 GOTOOLCHAIN=go${GO_VERSION} build.sh --deploy,"
echo "    # stages /opt/dnstool-stage, swaps, restarts, verifies --version + /healthz body"
echo "  CHECK: ./dns-tool-server --version  (real version, NOT 'dev'); /etc/dnstool/env has CLOUD_DEPLOYMENT=1"

# ---------------------------------------------------------------------------
# STEP 7 — First boot: verify migration 019 EXECUTES + freeze ends.
# ---------------------------------------------------------------------------
echo "== STEP 7: first boot verification =="
echo "  Watch for: stamp_through=18 -> adopted stamped=18 -> pending 18->19 -> schema upgraded applied=1"
echo "  stamp_through=19 = STOP (019 stamped not executed; score freeze reproduces)"
echo "  CHECK: both score tables data_type='text'; app_version column exists"
echo "  Fire a scan -> confirm new icuae_scan_scores row (first since Jun 20), length(app_version)~23"

# ---------------------------------------------------------------------------
# STEP 8 — Let's Encrypt certbot on the box (phase 1 TLS on EC2 directly).
# dnstool CAA authorizes letsencrypt (already present).
# ---------------------------------------------------------------------------
echo "== STEP 8: certbot (Let's Encrypt) for dnstool.it-help.tech =="
echo "  certbot --nginx (or standalone) -d dnstool.it-help.tech"
echo "  CHECK: https://dnstool.it-help.tech/healthz -> 200 AND body contains '\"status\":\"ok\"'"
echo "         (503 body for starting/degraded/crash-loop — a 200 alone routes traffic to a dying box)"
echo "  CHECK (post-#264 embed — wrong-cwd is now SILENT degradation, not a fatal exit):"
echo "    (a) fetch a VERSIONED static asset (/static/css/*.css?v=...) -> 200 AND its SRI integrity"
echo "        attribute present. Process liveness does NOT prove the deploy is correct — a"
echo "        healthz-only check passes while the site serves 404s / no SRI / stale assets."
echo "    (b) load /stats and confirm the integrity numbers RENDER (not just 200). The JSON read"
echo "        (static/data/integrity_stats.json) is a different path resolution from asset serving —"
echo "        a 200 on a CSS file does not prove the JSON resolved, even though both use ResolveStaticDir."

# ---------------------------------------------------------------------------
# STEP 9 — Flip Route53 to the Elastic IP.
# ---------------------------------------------------------------------------
echo "== STEP 9: Route53 dnstool.it-help.tech -> Elastic IP =="
echo "  CHECK: dig dnstool.it-help.tech -> Elastic IP; curl https://dnstool.it-help.tech -> 200"

# ---------------------------------------------------------------------------
# PHASE 2 (after stable direct cutover): CloudFront + ACM cert (us-east-1) +
# trusted-proxies. re-key/HSTS/health-503 are PHASE 1 (STEP 5.5, pre-cutover).
# CAA amazon.com already authorized on dnstool (done 2026-08-01).
# Backup-step additions when built out: S3 lifecycle-expiry for versions after
# lock lapse (compliance + nightly 347MB = unbounded growth) + newest-object-age
# >25h alarm (a stopped writer is silent otherwise).
# ---------------------------------------------------------------------------
echo "== phase 2 (later): CloudFront + ACM cert + trusted-proxies =="
echo "  - settle trusted-proxies (SetTrustedProxies, main.go:337) — localhost-only is correct for direct serving first"
echo "  - ACM cert dnstool.it-help.tech in us-east-1 (CAA authorized)"
echo "  - CloudFront: cache key includes query string, strip Set-Cookie, MinTTL=0, origin timeout>=60s"
echo "  - backup: S3 lifecycle-expiry for versions after lock lapse + newest-object-age>25h alarm"

echo "== bootstrap skeleton complete — fill placeholders (SG ids, subnet group, DB_PASSWORD) at run time =="
