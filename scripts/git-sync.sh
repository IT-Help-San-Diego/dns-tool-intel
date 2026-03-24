#!/bin/bash
# Git sync — push local changes to dns-tool-intel main via GitHub API.
# Usage: bash scripts/git-sync.sh
#
# Collects all tracked files, pushes them as a commit to main via the
# GitHub Trees/Commits API. No git-push required — works even when
# local and remote have unrelated histories.
#
# Uses ORG_PAT (or GITHUB_MASTER_PAT fallback) for authentication.
# Safe to run anytime. Fails loudly on any problem.

set -euo pipefail
cd "$(dirname "$0")/.."

REPO_OWNER="IT-Help-San-Diego"
REPO_NAME="dns-tool-intel"
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
echo "═══════════════════════════════════════════"
echo "  Git Sync → ${REPO_NAME}/main (API push)"
echo "  App version: v${VERSION}"
echo "═══════════════════════════════════════════"
echo ""

info "Pre-flight checks"

if ! git diff-index --quiet HEAD -- 2>/dev/null; then
  fail "Working tree is dirty. Commit or stash changes first."
fi
pass "Working tree clean"

LOCAL_MSG=$(git log -1 --format='%s' 2>/dev/null)
pass "Last commit: ${LOCAL_MSG}"

info "Comparing with remote"

REMOTE_TREE=$(python3 -c "
import os, json, urllib.request
token = os.environ.get('ORG_PAT') or os.environ['GITHUB_MASTER_PAT']
headers = {'Authorization': f'Bearer {token}', 'Accept': 'application/vnd.github.v3+json'}
req = urllib.request.Request('${API}/git/ref/heads/main', headers=headers)
ref = json.loads(urllib.request.urlopen(req).read())
sha = ref['object']['sha']
req2 = urllib.request.Request(f'${API}/git/commits/{sha}', headers=headers)
commit = json.loads(urllib.request.urlopen(req2).read())
print(commit['tree']['sha'])
" 2>/dev/null) || fail "Failed to read remote main"
pass "Remote main tree: ${REMOTE_TREE:0:12}"

info "Pushing changes via GitHub API"

RESULT=$(python3 << 'PYEOF'
import os, sys, json, urllib.request, base64, subprocess, hashlib, time

token = os.environ.get('ORG_PAT') or os.environ['GITHUB_MASTER_PAT']
repo = "IT-Help-San-Diego/dns-tool-intel"
api_base = f"https://api.github.com/repos/{repo}"
headers = {
    'Authorization': f'Bearer {token}',
    'Accept': 'application/vnd.github.v3+json',
    'Content-Type': 'application/json'
}

def api(method, url, data=None, retries=3):
    body = json.dumps(data).encode() if data else None
    for attempt in range(retries):
        try:
            req = urllib.request.Request(f'https://api.github.com{url}', data=body, headers=headers, method=method)
            resp = urllib.request.urlopen(req)
            return json.loads(resp.read())
        except urllib.error.HTTPError as e:
            if e.code in (403, 429, 502, 503) and attempt < retries - 1:
                wait = (attempt + 1) * 5
                print(f"  API {e.code}, retrying in {wait}s... ({url})", file=sys.stderr)
                time.sleep(wait)
            else:
                raise

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

intel_files = subprocess.run(
    ['find', '.', '-name', '*_intel.go', '-not', '-path', './.git/*', '-not', '-path', './node_modules/*'],
    capture_output=True, text=True
).stdout.strip().split('\n')
intel_files = [f.lstrip('./') for f in intel_files if f]
tracked_set = set(tracked)
for f in intel_files:
    if f not in tracked_set and os.path.isfile(f):
        tracked.append(f)
        tracked_set.add(f)

changed = []
for fpath in tracked:
    if not os.path.isfile(fpath):
        continue
    try:
        with open(fpath, 'rb') as f:
            content = f.read()
    except:
        continue
    blob_header = f"blob {len(content)}\0".encode()
    local_sha = hashlib.sha1(blob_header + content).hexdigest()
    if fpath not in remote_files or remote_files[fpath] != local_sha:
        changed.append(fpath)

for rpath in remote_files:
    if rpath not in tracked and os.path.isfile(rpath):
        pass

if not changed:
    print("UP_TO_DATE")
    sys.exit(0)

print(f"PUSHING {len(changed)} file(s)", file=sys.stderr)

tree_entries = []
batch_size = 20
for i in range(0, len(changed), batch_size):
    batch = changed[i:i+batch_size]
    for fpath in batch:
        with open(fpath, 'rb') as f:
            content = f.read()
        is_text = True
        try:
            text_content = content.decode('utf-8')
        except UnicodeDecodeError:
            is_text = False
        if is_text:
            blob = api('POST', f'/repos/{repo}/git/blobs', {
                'content': text_content,
                'encoding': 'utf-8'
            })
        else:
            blob = api('POST', f'/repos/{repo}/git/blobs', {
                'content': base64.b64encode(content).decode(),
                'encoding': 'base64'
            })
        tree_entries.append({
            'path': fpath,
            'mode': '100644',
            'type': 'blob',
            'sha': blob['sha']
        })
    print(f"  uploaded {min(i+batch_size, len(changed))}/{len(changed)}", file=sys.stderr)
    time.sleep(0.5)

new_tree = api('POST', f'/repos/{repo}/git/trees', {
    'base_tree': old_tree_sha,
    'tree': tree_entries
})

if new_tree['sha'] == old_tree_sha:
    print("UP_TO_DATE")
    sys.exit(0)

version = subprocess.run(
    ['grep', 'Version.*=', 'go-server/internal/config/config.go'],
    capture_output=True, text=True
).stdout.strip()
version = version.split('"')[1] if '"' in version else 'unknown'

last_msg = subprocess.run(['git', 'log', '-1', '--format=%s'], capture_output=True, text=True).stdout.strip()
commit_msg = f"v{version}: {last_msg}\n\nSynced from Replit workspace via API"

new_commit = api('POST', f'/repos/{repo}/git/commits', {
    'message': commit_msg,
    'tree': new_tree['sha'],
    'parents': [main_sha]
})

api('PATCH', f'/repos/{repo}/git/refs/heads/main', {'sha': new_commit['sha']})

# Also update replit-agent branch to match
try:
    api('PATCH', f'/repos/{repo}/git/refs/heads/replit-agent', {'sha': new_commit['sha'], 'force': True})
except:
    try:
        api('POST', f'/repos/{repo}/git/refs', {'ref': 'refs/heads/replit-agent', 'sha': new_commit['sha']})
    except:
        pass

print(f"PUSHED {len(changed)} {new_commit['sha'][:12]}")
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
pass "Pushed ${FILE_COUNT} changed file(s) → main (${COMMIT_SHA})"

echo ""
echo "═══════════════════════════════════════════"
echo -e "  ${GREEN}Done.${NC} v${VERSION} is on ${REPO_NAME}/main."
echo "═══════════════════════════════════════════"
echo ""
