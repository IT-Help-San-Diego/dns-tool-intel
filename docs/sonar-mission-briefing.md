# SonarCloud Mission Briefing

## Date: March 25, 2026
## Current Version: 26.38.34
## Target Project: `dns-tool-full` → "DNS Tool · Canonical Build (dns-tool-intel)"

---

## Recent Changes (Since ~v26.38.30)

### Footer Overhaul (v26.38.30–v26.38.32)
- Complete footer organizational topology tree: IT Help San Diego Inc. → Delaware/California registrations → T-junction with Research Department + Professional Consulting → DNS Tool below Research
- Per-link contextual icons across all 21 footer links
- Grid cards reorganized into 4 categories: Research (6), Platform (6), Governance (4), Company (4)
- All inline CSS in `_footer.html` (no external stylesheet changes)
- **Files changed**: `go-server/templates/_footer.html`

### Documentation Updates (v26.38.32)
- `llms.txt` and `llms-full.txt`: Added 12+ missing page entries (corpus, cite, reference-library, publications, owl-semaphore, manifesto, communication-standards, roe, contact, security-policy, privacy, topology, case-study)
- `changelog.go`: New entry for Footer Organizational Topology Tree, fixed "Legal" → "Company" in older entry
- `replit.md`: Added footer topology tree to UI/UX Decisions section
- **Files changed**: `go-server/static/llms.txt`, `go-server/static/llms-full.txt`, `static/llms.txt`, `static/llms-full.txt`, `go-server/internal/handlers/changelog.go`, `replit.md`

### SonarCloud Naming (v26.38.34)
- `sonar-project.properties`: Renamed project to "DNS Tool · Canonical Build (dns-tool-intel)"
- `mirror-to-web.yml`: Updated sed to rename public mirror to "DNS Tool · Public Mirror (dns-tool-web)"
- **Files changed**: `sonar-project.properties`, `.github/workflows/mirror-to-web.yml`

### Dependabot Dependency Updates (v26.38.34)
All 8 open Dependabot PRs on dns-tool-intel resolved in-tree:
- **Go**: `gin-gonic/gin` 1.11.0 → 1.12.0, `jackc/pgx/v5` 5.8.0 → 5.9.1
- **npm**: `typescript` 5.9.3 → 6.0.2, `ws` 8.19.0 → 8.20.0, `terser` 5.46.0 → 5.46.1, `@notionhq/client` 2.3.0 → 5.14.0, `@replit/connectors-sdk` 0.2.0 → 0.3.0
- **CI**: `actions/upload-artifact` v6 → v7
- **TS 6 fix**: Added `"types": ["node"]` to `go-server/tools/topology-solver/tsconfig.json` for TypeScript 6 compatibility
- **Files changed**: `go.mod`, `go.sum`, `package.json`, `package-lock.json`, `go-server/tools/topology-solver/tsconfig.json`, `.github/workflows/cross-browser-tests.yml`

---

## Current SonarCloud State (dns-tool-full)

### Overall Ratings
| Metric | Value | Grade |
|---|---|---|
| Security | 0 vulnerabilities | A |
| Reliability | 8 bugs | C |
| Maintainability | 167 code smells | A |
| Coverage | 74.7% | — |
| Duplications | 2.3% | — |
| Lines of Code | 102,008 | — |

### Quality Gate: PASSED ✅
AI Code Assurance: PASSED ✅

### What's Failing the Gate on Other Projects
- `dns-tool-web` (Public Mirror): FAILS — because `_intel.go` files are stripped, so coverage drops and some stubs trigger issues
- `careyjames_dns-tool-intel` and `careyjames_dns-tool`: Auto-imported duplicates from pre-org-migration. Recommend DELETING from SonarCloud — they're redundant.

---

## Issue Breakdown

### Bugs (8 total — this is why Reliability is C, not A)
| Severity | File | Issue |
|---|---|---|
| MINOR | `templates/black_site.html:691` | Mouse event without keyboard equivalent (h2 onclick) |
| MINOR | `templates/black_site.html:719` | Mouse event without keyboard equivalent (h2 onclick) |
| MAJOR | `static/references/AD0639176-snapshot.html:10` | Missing generic font family (3 instances) |
| MAJOR | `static/references/AD0639176-snapshot.html:12` | Duplicate "height" property |
| MINOR | `templates/compare_select.html:65` | Mouse event without keyboard equivalent (tr onclick) |
| MAJOR | `templates/results.html:2959` | Table missing `<th>` headers |

**Strategy**: The `AD0639176-snapshot.html` is a static reference document snapshot — consider excluding it via `sonar.exclusions`. The black_site and compare_select mouse events need `onKeyDown` equivalents. The results.html table needs `<th>` headers.

### Critical/Blocker Issues (57 total)
All are JavaScript — concentrated in **3 rules**:
| Count | Rule | Description |
|---|---|---|
| 47 | `javascript:S3504` | `var` instead of `let`/`const` |
| 7 | `javascript:S2004` | Functions declared inside loops |
| 3 | `javascript:S3776` | Cognitive complexity too high |

**All 47 `var` issues are in `go-server/static/js/main.js`** — a single `var` → `let`/`const` sweep of main.js would eliminate 82% of critical issues.

### Code Smells (167 total) — Top Files
| Count | File | Primary Rules |
|---|---|---|
| 52 | `static/js/main.js` | S3504 (var), S7764, S2486, S6582, S4138 |
| 25 | `static/references/AD0639176-snapshot.html` | S4666 (CSS issues in static snapshot) |
| 5 | `templates/corpus.html` | Web template issues |
| 5 | `templates/video_forgotten_domain.html` | Web issues |
| 4 | `templates/black_site.html` | Web issues |
| 4 | `templates/case_study_intelligence_dmarc.html` | Web issues |
| 2 | `internal/logging/schema.go` | Go code smells |

### Code Smell Rule Breakdown (All 167)
| Count | Rule | What It Means |
|---|---|---|
| 47 | `javascript:S3504` | Use `let`/`const` instead of `var` |
| 32 | `javascript:S7764` | Nullish coalescing / optional chaining suggestions |
| 11 | `css:S4666` | CSS issues (mostly in the reference snapshot) |
| 10 | `Web:S6827` | HTML template issues |
| 10 | `javascript:S7761` | Logical assignment operators |
| 9 | `Web:S7927` | HTML issues |
| 7 | `javascript:S2004` | Functions in loops |
| 7 | `javascript:S2486` | Empty catch blocks |
| 6 | `javascript:S6582` | Optional chaining |
| 5 | `Web:S6819` | ARIA role issues |
| 5 | `javascript:S4138` | `for...of` instead of `forEach` |
| 3 | `javascript:S3776` | Cognitive complexity |
| 2 | `Web:S6842` | ARIA tablist role |
| 2 | `javascript:S7773` | JS issues |
| 2 | `godre:S8209` | Go code smells |

---

## Mission Strategy: Path to All-A Ratings

### Priority 1: Fix Reliability (C → A) — Kill the 8 Bugs
1. **Exclude `static/references/AD0639176-snapshot.html`** from Sonar analysis (it's a frozen third-party document snapshot, not your code). Add to `sonar.exclusions`. This kills 4 bugs + 25 code smells instantly.
2. **Add keyboard handlers** to `black_site.html` (lines 691, 719) and `compare_select.html` (line 65) — add `onkeydown` or use `<button>` elements instead of click-only `<h2>`/`<tr>`.
3. **Add `<th>` headers** to the table in `results.html` around line 2959.

### Priority 2: Eliminate Critical/Blocker Issues (57 → 0)
1. **Sweep `main.js`**: Replace all `var` with `let` or `const`. This single change kills 47 of 57 critical issues. Be careful: `var` has function scope while `let`/`const` have block scope — test after each change.
2. **Fix functions-in-loops** (7 issues in main.js): Extract loop-body functions to named declarations outside the loop.
3. **Reduce cognitive complexity** (3 functions in main.js): Break complex functions into smaller helpers.

### Priority 3: Reduce Code Smells (167 → target <50)
1. After excluding the reference snapshot: 167 → ~142
2. After the main.js var sweep: 142 → ~95
3. Modern JS patterns in main.js (nullish coalescing, optional chaining, for...of): 95 → ~50
4. Template HTML fixes (ARIA roles, Web rules): 50 → ~30

### Important Constraints
- **SRI hashes**: After ANY change to `static/js/main.js` or `static/css/custom.min.css`, you MUST rebuild the Go binary. SRI hashes are computed at server startup by `InitSRI()` in `go-server/internal/templates/funcs.go`. If you don't rebuild, the browser will reject the modified assets.
- **Two static directories**: Changes to files in `go-server/static/` must also be reflected in `static/` (or vice versa). Keep them in sync.
- **CSP nonces**: All inline scripts use `nonce="{{.CspNonce}}"`. Don't add inline event handlers — use `addEventListener` in nonce'd script blocks.
- **Build command**: `cd go-server && go build -o ../dns-tool-server ./cmd/server/`
- **Test command**: `go test ./go-server/... -count=1 -short`
- **Minification**: After editing `main.js`, run the minifier to update `main.min.js` (check existing build scripts).
- **Quality gates**: Lighthouse 100, Observatory 145+ (A+), SonarCloud A/A/A are Standing Gates — they must all pass.

### Quick Wins (Do These First)
1. Add `static/references/AD0639176-snapshot.html` to `sonar.exclusions` → kills 4 bugs + 25 smells
2. `var` → `let`/`const` in main.js → kills 47 criticals + 47 smells
3. Keyboard handlers on 3 elements → kills 3 bugs
4. Table headers in results.html → kills 1 bug

**After these 4 changes: 0 bugs, 0 criticals, ~90 code smells remaining. Reliability jumps to A.**

---

## SonarCloud Project Cleanup
The following auto-imported projects are redundant and should be deleted from SonarCloud:
- `careyjames_dns-tool` (key: `careyjames_dns-tool`) — duplicate of dns-tool-web
- `careyjames_dns-tool-intel` (key: `careyjames_dns-tool-intel`) — duplicate of dns-tool-full

The two canonical projects going forward:
- **`dns-tool-full`** → "DNS Tool · Canonical Build (dns-tool-intel)" — THE quality gate
- **`dns-tool-web`** → "DNS Tool · Public Mirror (dns-tool-web)" — open-source mirror
