#!/usr/bin/env bash
# One-command release: bumps versions, validates, commits, syncs, tags, pushes.
# Usage: ./scripts/release.sh X.Y.Z
#
# Prerequisites:
#   - Clean working tree (no uncommitted changes)
#   - GITHUB_MASTER_PAT set with repo + workflow scope
#
# What it does:
#   1. Runs release-gate.sh (bumps all versioned artifacts, regenerates PDFs, validates)
#   2. Commits the release locally
#   3. Syncs to dns-tool-intel (private, canonical dev repo) via git-sync.sh
#   4. Pushes to dns-tool-web (public mirror) via GitHub API, excluding _intel.go files
#   5. Creates annotated tag vX.Y.Z on dns-tool-web (where Zenodo watches)
#   6. GitHub Actions creates the Release with SHA256SUMS (automatic)
#   7. Zenodo auto-archives via GitHub integration (automatic)
#
# Architecture:
#   This workspace is dns-tool-intel (private). Zenodo watches dns-tool-web (public).
#   The release must land on dns-tool-web with _intel.go files stripped.

set -euo pipefail
cd "$(dirname "$0")/.."

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

pass() { echo -e "  ${GREEN}✓${NC} $1"; }
fail() { echo -e "  ${RED}✗ $1${NC}"; exit 1; }
info() { echo -e "${YELLOW}▸${NC} $1"; }

trap 'echo ""; echo -e "  ${RED}✗ Release pipeline failed at line $LINENO: $BASH_COMMAND${NC}"; echo "  Fix the error above and re-run: bash scripts/release.sh $1"' ERR

if [[ $# -ne 1 ]]; then
  echo "Usage: $0 X.Y.Z"
  exit 1
fi

VER="$1"
TAG="v$VER"

if [[ "$VER" == v* ]]; then
  fail "Version must NOT have a leading 'v' (got: $VER). Use: ${VER#v}"
fi

if [[ ! "$VER" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  fail "Version must be X.Y.Z format (got: $VER)"
fi

TOKEN="${GH_SYNC_TOKEN:-${ORG_PAT:-${GITHUB_MASTER_PAT:-}}}"
if [ -z "$TOKEN" ]; then
  fail "GH_SYNC_TOKEN (or ORG_PAT) not set. Cannot authenticate with GitHub."
fi

if ! git diff-index --quiet HEAD -- 2>/dev/null; then
  fail "Working tree is not clean. Commit or stash changes before releasing."
fi

INTEL_REPO="IT-Help-San-Diego/dns-tool-intel"
WEB_REPO="IT-Help-San-Diego/dns-tool-web"

echo ""
echo -e "${YELLOW}═══════════════════════════════════════════════════${NC}"
echo -e "${YELLOW}  Release Pipeline — ${TAG}${NC}"
echo -e "${YELLOW}  intel → dns-tool-intel (private)${NC}"
echo -e "${YELLOW}  public → dns-tool-web (Zenodo-watched)${NC}"
echo -e "${YELLOW}═══════════════════════════════════════════════════${NC}"
echo ""

echo -e "${YELLOW}Step 1/5${NC}: Running release gate (version bump + validation)..."
echo ""
bash scripts/release-gate.sh "$VER"

echo ""
echo -e "${YELLOW}Step 2/5${NC}: Committing release locally..."
git add -A
git status --short
git commit -m "Release ${TAG}"
pass "Committed: Release ${TAG}"

echo ""
echo -e "${YELLOW}Step 3/5${NC}: Syncing to dns-tool-intel (private)..."
bash scripts/git-sync.sh
pass "dns-tool-intel synced"

echo ""
echo -e "${YELLOW}Step 4/5${NC}: Pushing to dns-tool-web (public, excluding _intel.go)..."
echo ""

WEB_COMMIT_SHA=$(python3 << PYEOF
import os, sys, json, urllib.request, base64, subprocess, hashlib, time

token = os.environ.get('GH_SYNC_TOKEN') or os.environ.get('ORG_PAT') or os.environ.get('GITHUB_MASTER_PAT', '')
repo = "${WEB_REPO}"
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
            resp = urllib.request.urlopen(req, timeout=30)
            return json.loads(resp.read())
        except urllib.error.HTTPError as e:
            err_body = ''
            try:
                err_body = e.read().decode('utf-8', errors='replace')
            except:
                pass
            if e.code in (403, 429, 502, 503) and attempt < retries - 1:
                wait = (attempt + 1) * 5
                print(f"  API {e.code}, retrying in {wait}s... ({url})", file=sys.stderr)
                time.sleep(wait)
            else:
                print(f"  API {e.code} on {method} {url}: {err_body[:500]}", file=sys.stderr)
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

public_excludes = set()
excludes_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'public-excludes.txt')
if not os.path.isfile(excludes_path):
    excludes_path = os.path.join(os.getcwd(), 'scripts', 'public-excludes.txt')
if os.path.isfile(excludes_path):
    with open(excludes_path) as ef:
        for line in ef:
            line = line.strip()
            if line and not line.startswith('#'):
                public_excludes.add(line)
    print(f"Loaded {len(public_excludes)} path(s) from public-excludes.txt", file=sys.stderr)

excluded = []
included = []
for fpath in tracked:
    if '_intel.go' in fpath or '_intel_test.go' in fpath or fpath in public_excludes:
        excluded.append(fpath)
    else:
        included.append(fpath)

if excluded:
    print(f"EXCLUDED {len(excluded)} intel/proprietary file(s)", file=sys.stderr)
    for ef in excluded:
        print(f"  skip: {ef}", file=sys.stderr)

changed = []
for fpath in included:
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

deleted = []
for rpath in remote_files:
    if rpath not in included:
        if '_intel.go' not in rpath and '_intel_test.go' not in rpath:
            deleted.append(rpath)

for rpath in remote_files:
    if rpath in public_excludes and rpath not in deleted:
        deleted.append(rpath)
        print(f"  purge (public-excludes): {rpath}", file=sys.stderr)

if not changed and not deleted:
    print("UP_TO_DATE", file=sys.stderr)
    print(main_sha)
    sys.exit(0)

print(f"PUSHING {len(changed)} changed, {len(deleted)} deleted", file=sys.stderr)

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
        if is_text and fpath == 'sonar-project.properties':
            import re as _re
            text_content = text_content.replace('sonar.projectKey=dns-tool-full', 'sonar.projectKey=dns-tool-web')
            text_content = _re.sub(r'sonar\.projectName=.*', 'sonar.projectName=DNS Tool · Public Mirror (dns-tool-web)', text_content)
            content = text_content.encode('utf-8')
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
    uploaded = min(i+batch_size, len(changed))
    total = len(changed)
    print(f"  uploaded {uploaded}/{total}", file=sys.stderr)
    time.sleep(0.5)

for dpath in deleted:
    tree_entries.append({
        'path': dpath,
        'mode': '100644',
        'type': 'blob',
        'sha': None
    })

web_wf_dir = os.path.join(os.getcwd(), '.github', 'workflows-web')
if os.path.isdir(web_wf_dir):
    for wf_name in os.listdir(web_wf_dir):
        wf_path = os.path.join(web_wf_dir, wf_name)
        with open(wf_path, 'r') as wf:
            wf_content = wf.read()
        wf_blob = api('POST', f'/repos/{repo}/git/blobs', {
            'content': wf_content,
            'encoding': 'utf-8'
        })
        dest_path = f'.github/workflows/{wf_name}'
        tree_entries.append({
            'path': dest_path,
            'mode': '100644',
            'type': 'blob',
            'sha': wf_blob['sha']
        })
    print(f"  Added {len(os.listdir(web_wf_dir))} web workflow(s) to tree", file=sys.stderr)

new_tree = api('POST', f'/repos/{repo}/git/trees', {
    'base_tree': old_tree_sha,
    'tree': tree_entries
})

new_commit = api('POST', f'/repos/{repo}/git/commits', {
    'message': 'Release ${TAG}\n\nAll versioned artifacts bumped to ${VER}.\nPDFs regenerated. Quality gates passed.\nSynced from dns-tool-intel via release pipeline.',
    'tree': new_tree['sha'],
    'parents': [main_sha]
})

merge_sha = new_commit['sha']

try:
    api('PATCH', f'/repos/{repo}/git/refs/heads/main', {'sha': merge_sha})
    print(merge_sha, end='')
except urllib.error.HTTPError as e:
    if e.code == 422:
        print("  Branch protected — using PR merge flow", file=sys.stderr)
        branch_name = "release/${TAG}"
        try:
            api('DELETE', f'/repos/{repo}/git/refs/heads/' + branch_name)
            print("  Cleaned up stale branch " + branch_name, file=sys.stderr)
        except:
            pass
        api('POST', f'/repos/{repo}/git/refs', {
            'ref': 'refs/heads/' + branch_name,
            'sha': merge_sha
        })
        pr = api('POST', f'/repos/{repo}/pulls', {
            'title': 'Release ${TAG}',
            'head': branch_name,
            'base': 'main',
            'body': 'Release ${TAG} — all versioned artifacts bumped to ${VER}.\nPDFs regenerated. Quality gates passed.\nSynced from dns-tool-intel via release pipeline.'
        })
        pr_number = pr['number']
        print("  PR #" + str(pr_number) + " created", file=sys.stderr)
        time.sleep(2)
        merge_result = api('PUT', f'/repos/{repo}/pulls/' + str(pr_number) + '/merge', {
            'commit_title': 'Release ${TAG} (#' + str(pr_number) + ')',
            'merge_method': 'squash'
        })
        if not merge_result.get('merged'):
            print("  Merge failed: " + str(merge_result), file=sys.stderr)
            sys.exit(1)
        final_sha = merge_result['sha']
        print("  PR #" + str(pr_number) + " merged -> " + final_sha[:12], file=sys.stderr)
        try:
            api('DELETE', f'/repos/{repo}/git/refs/heads/' + branch_name)
        except:
            pass
        print(final_sha, end='')
    else:
        raise
PYEOF
) || fail "Failed to push to dns-tool-web"

pass "dns-tool-web updated (${WEB_COMMIT_SHA:0:12})"

echo ""
echo -e "${YELLOW}Step 5/5${NC}: Creating tag ${TAG} on dns-tool-web..."

python3 << PYEOF
import os, sys, json, urllib.request, time

token = os.environ.get('GH_SYNC_TOKEN') or os.environ.get('ORG_PAT') or os.environ.get('GITHUB_MASTER_PAT', '')
repo = "${WEB_REPO}"
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
            resp = urllib.request.urlopen(req, timeout=30)
            return json.loads(resp.read())
        except urllib.error.HTTPError as e:
            if e.code in (403, 429, 502, 503) and attempt < retries - 1:
                time.sleep((attempt + 1) * 5)
            else:
                raise

web_sha = "${WEB_COMMIT_SHA}"
if not web_sha or len(web_sha) < 10:
    ref = api('GET', f'/repos/{repo}/git/ref/heads/main')
    web_sha = ref['object']['sha']
    print(f"  Using main HEAD: {web_sha[:12]}", file=sys.stderr)

try:
    api('DELETE', f'/repos/{repo}/git/refs/tags/${TAG}')
    print("  Replaced existing tag", file=sys.stderr)
except:
    pass

tag_obj = api('POST', f'/repos/{repo}/git/tags', {
    'tag': '${TAG}',
    'message': '${TAG}',
    'object': web_sha,
    'type': 'commit',
    'tagger': {
        'name': 'Carey James Balboa',
        'email': 'carey@it-help.tech',
        'date': __import__('datetime').datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
    }
})

api('POST', f'/repos/{repo}/git/refs', {
    'ref': 'refs/tags/${TAG}',
    'sha': tag_obj['sha']
})
PYEOF
[ $? -eq 0 ] || fail "Failed to create tag on dns-tool-web"

pass "Tag ${TAG} created on dns-tool-web"

echo ""
echo -e "${GREEN}═══════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  Release ${TAG} complete${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════${NC}"
echo ""
echo "What happened:"
echo "  1. All versioned artifacts bumped to ${VER}"
echo "  2. PDFs regenerated (methodology, foundations, manifesto, comm standards)"
echo "  3. CITATION.cff version + date updated"
echo "  4. Go tests + quality gates passed"
echo "  5. Committed locally + synced to dns-tool-intel (private)"
echo "  6. Pushed to dns-tool-web (public, _intel.go excluded)"
echo "  7. Tag ${TAG} created on dns-tool-web"
echo ""
echo "Next (automatic — no action needed):"
echo "  1. GitHub Actions creates Release with SHA256SUMS"
echo "  2. Zenodo auto-archives the GitHub Release"
echo ""
echo "Verify:"
echo "  - GitHub: https://github.com/${WEB_REPO}/releases/tag/${TAG}"
echo "  - Zenodo: https://zenodo.org/doi/10.5281/zenodo.18854899"
echo ""
