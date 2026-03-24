#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."

REPO_OWNER="IT-Help-San-Diego"
REPO_NAME="dns-tool-web"
API="https://api.github.com/repos/${REPO_OWNER}/${REPO_NAME}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

pass() { echo -e "  ${GREEN}✓${NC} $1"; }
fail() { echo -e "  ${RED}✗ $1${NC}"; exit 1; }
info() { echo -e "${YELLOW}▸${NC} $1"; }

TOKEN="${ORG_PAT:-${GITHUB_MASTER_PAT:-}}"
if [ -z "$TOKEN" ]; then
  fail "ORG_PAT not set. Cannot authenticate with GitHub."
fi

VERSION=$(grep 'Version.*=' go-server/internal/config/config.go | head -1 | sed 's/.*"\(.*\)".*/\1/')
echo ""
echo "═══════════════════════════════════════════════════════"
echo "  OSS Sync → ${REPO_NAME}/main (filtered, API push)"
echo "  App version: v${VERSION}"
echo "  Proprietary files will be EXCLUDED"
echo "═══════════════════════════════════════════════════════"
echo ""

if ! git diff-index --quiet HEAD -- 2>/dev/null; then
  fail "Working tree is dirty. Commit or stash changes first."
fi
pass "Working tree clean"

LOCAL_MSG=$(git log -1 --format='%s' 2>/dev/null)
pass "Last commit: ${LOCAL_MSG}"

info "Syncing to ${REPO_NAME} (public OSS repo — proprietary code stripped)"

RESULT=$(python3 << 'PYEOF'
import os, sys, json, urllib.request, base64, subprocess, hashlib, re, time

token = os.environ.get('ORG_PAT') or os.environ['GITHUB_MASTER_PAT']
repo = "IT-Help-San-Diego/dns-tool-web"
api_base = f"https://api.github.com/repos/{repo}"
headers = {
    'Authorization': f'Bearer {token}',
    'Accept': 'application/vnd.github.v3+json',
    'Content-Type': 'application/json'
}

call_count = 0

def api(method, url, data=None, retries=5):
    global call_count
    body = json.dumps(data).encode() if data else None
    for attempt in range(retries):
        try:
            req = urllib.request.Request(f'https://api.github.com{url}', data=body, headers=headers, method=method)
            resp = urllib.request.urlopen(req)
            call_count += 1
            if call_count % 50 == 0:
                time.sleep(1)
            return json.loads(resp.read())
        except urllib.error.HTTPError as e:
            if e.code in (403, 429) and attempt < retries - 1:
                wait = min(10 * (attempt + 1), 60)
                print(f"  rate-limited ({e.code}), retrying in {wait}s (attempt {attempt+1}/{retries})...", file=sys.stderr)
                time.sleep(wait)
            else:
                raise

EXCLUDE_DIRS = {
    'providers',
    'ai_surface',
    'stubs',
    '.local',
    '.agents',
    'attached_assets',
    'node_modules',
}

EXCLUDE_FILES = {
    'scripts/github-intel-sync.mjs',
    'scripts/codeberg-intel-sync.mjs',
    'scripts/sync-pipeline.mjs',
    'scripts/sync-mermaid-miro.mjs',
    'scripts/figma-asset-bundle.mjs',
    'scripts/figma-verify.mjs',
    'scripts/notion-control-plane.mjs',
    'scripts/notion-roadmap-sync.mjs',
    'scripts/verify-pipeline-sync.mjs',
    'scripts/pipeline-config.json',
    'scripts/gptzero-scan.mjs',
    'scripts/gptzero-results.json',
    'scripts/moltbook-checkin.py',
}

def is_excluded(fpath):
    parts = fpath.split('/')
    if parts[0] in EXCLUDE_DIRS:
        return True
    if fpath in EXCLUDE_FILES:
        return True
    if fpath.endswith('_intel.go'):
        return True
    if fpath.startswith('.canvas/'):
        return True
    return False

def has_intel_build_tag(fpath):
    if not fpath.endswith('.go'):
        return False
    try:
        with open(fpath, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('//'):
                    if '//go:build intel' in line:
                        return True
                    continue
                break
    except:
        pass
    return False

ref = api('GET', f'/repos/{repo}/git/ref/heads/main')
main_sha = ref['object']['sha']
commit = api('GET', f'/repos/{repo}/git/commits/{main_sha}')
old_tree_sha = commit['tree']['sha']

old_tree = api('GET', f'/repos/{repo}/git/trees/{old_tree_sha}?recursive=1')
remote_files = {}
for entry in old_tree['tree']:
    if entry['type'] == 'blob':
        remote_files[entry['path']] = entry['sha']

tracked = subprocess.run(['git', 'ls-files'], capture_output=True, text=True).stdout.strip().split('\n')
tracked = [f for f in tracked if f]

eligible = []
excluded_count = 0
intel_tagged_count = 0
for fpath in tracked:
    if is_excluded(fpath):
        excluded_count += 1
        continue
    if not os.path.isfile(fpath):
        continue
    if has_intel_build_tag(fpath):
        intel_tagged_count += 1
        continue
    eligible.append(fpath)

print(f"ELIGIBLE {len(eligible)} files (excluded {excluded_count} dir/file rules, {intel_tagged_count} intel-tagged)", file=sys.stderr)

changed = []
for fpath in eligible:
    try:
        with open(fpath, 'rb') as f:
            content = f.read()
    except:
        continue
    blob_header = f"blob {len(content)}\0".encode()
    local_sha = hashlib.sha1(blob_header + content).hexdigest()
    if fpath not in remote_files or remote_files[fpath] != local_sha:
        changed.append(fpath)

to_delete = []
for rpath in remote_files:
    if rpath not in eligible:
        if is_excluded(rpath) or has_intel_build_tag(rpath) if rpath.endswith('.go') and os.path.isfile(rpath) else is_excluded(rpath):
            to_delete.append(rpath)

if not changed and not to_delete:
    print("UP_TO_DATE")
    sys.exit(0)

print(f"PUSHING {len(changed)} changed, {len(to_delete)} to delete", file=sys.stderr)

version = subprocess.run(
    ['grep', 'Version.*=', 'go-server/internal/config/config.go'],
    capture_output=True, text=True
).stdout.strip()
version = version.split('"')[1] if '"' in version else 'unknown'

last_msg = subprocess.run(['git', 'log', '-1', '--format=%s'], capture_output=True, text=True).stdout.strip()

def upload_blob(fpath):
    with open(fpath, 'rb') as f:
        content = f.read()
    try:
        text_content = content.decode('utf-8')
        return api('POST', f'/repos/{repo}/git/blobs', {
            'content': text_content,
            'encoding': 'utf-8'
        })
    except UnicodeDecodeError:
        return api('POST', f'/repos/{repo}/git/blobs', {
            'content': base64.b64encode(content).decode(),
            'encoding': 'base64'
        })

chunk_size = 200
all_items = list(changed) + [None]
chunks = [all_items[i:i+chunk_size] for i in range(0, len(all_items), chunk_size)]
if to_delete:
    if len(chunks[-1]) + len(to_delete) <= chunk_size:
        chunks[-1] = [x for x in chunks[-1] if x is not None] + [('DEL', d) for d in to_delete] + [None]
    else:
        chunks.append([('DEL', d) for d in to_delete])

current_tree_sha = old_tree_sha
parent_sha = main_sha
total_pushed = 0

for ci, chunk in enumerate(chunks):
    tree_entries = []
    for item in chunk:
        if item is None:
            continue
        if isinstance(item, tuple) and item[0] == 'DEL':
            tree_entries.append({
                'path': item[1],
                'mode': '100644',
                'type': 'blob',
                'sha': None
            })
            print(f"  queued delete: {item[1]}", file=sys.stderr)
        else:
            blob = upload_blob(item)
            tree_entries.append({
                'path': item,
                'mode': '100644',
                'type': 'blob',
                'sha': blob['sha']
            })
            total_pushed += 1
            if total_pushed % 20 == 0:
                print(f"  uploaded {total_pushed}/{len(changed)}", file=sys.stderr)

    if not tree_entries:
        continue

    new_tree = api('POST', f'/repos/{repo}/git/trees', {
        'base_tree': current_tree_sha,
        'tree': tree_entries
    })

    if new_tree['sha'] == current_tree_sha:
        continue

    chunk_num = f" ({ci+1}/{len(chunks)})" if len(chunks) > 1 else ""
    commit_msg = f"v{version}: {last_msg}{chunk_num}\n\nSynced from dns-tool-intel (proprietary files excluded)"

    new_commit = api('POST', f'/repos/{repo}/git/commits', {
        'message': commit_msg,
        'tree': new_tree['sha'],
        'parents': [parent_sha]
    })

    api('PATCH', f'/repos/{repo}/git/refs/heads/main', {'sha': new_commit['sha']})

    current_tree_sha = new_tree['sha']
    parent_sha = new_commit['sha']
    print(f"  committed chunk {ci+1}/{len(chunks)} → {new_commit['sha'][:12]}", file=sys.stderr)

print(f"PUSHED {total_pushed} {parent_sha[:12]}")
PYEOF
) || fail "API push failed"

if [ "$RESULT" = "UP_TO_DATE" ]; then
  pass "Already up to date — nothing to push"
  echo ""
  echo "All good. Nothing to do."
  exit 0
fi

COMMIT_SHA=$(echo "$RESULT" | grep "^PUSHED" | awk '{print $3}')
FILE_COUNT=$(echo "$RESULT" | grep "^PUSHED" | awk '{print $2}')
pass "Pushed ${FILE_COUNT} changed file(s) → ${REPO_NAME}/main (${COMMIT_SHA})"

echo ""
echo "═══════════════════════════════════════════════════════"
echo -e "  ${GREEN}Done.${NC} v${VERSION} synced to ${REPO_NAME}/main."
echo "  Proprietary code excluded. Public repo is clean."
echo "═══════════════════════════════════════════════════════"
echo ""
