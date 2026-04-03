---
name: dns-tool
description: DNS Tool project rules, architecture, and conventions. Use whenever working on this project — covers build tags, stub contracts, CSP constraints, testing requirements, version bumps, naming conventions, and critical anti-patterns to avoid.
---

# DNS Tool — Agent Skill

This skill contains the critical rules and architecture knowledge for the DNS Tool project. Load this before making any changes.

> **STOP. Before you do ANYTHING, read the "Step 0: Connected Ecosystem Pre-Flight" in the Session Startup section below.** You have access to 15+ API keys, 2 OAuth integrations, 1 MCP server (Figma; Miro and Notion MCP are currently disconnected), and 10+ connected knowledge systems. That changes how you should approach every single task. Come home to the data.

## Replit Platform Constraints (Empirically Tested Feb 18, 2026)

The platform monitors all file operations from the agent process tree. Writing to `.git/` triggers immediate process tree termination (exit 254).

**SAFE from agent (read-only):**
- `git rev-parse`, `git branch --show-current`, `git log`, `git diff`
- `git ls-remote` (network read)
- `git push` via PAT URL (network write, no local .git mutation)
- `cat .git/*` (reading any .git file)

**KILLS PROCESS (any .git write):**
- `git status` (creates `.git/index.lock`)
- `git fetch` (writes `.git/FETCH_HEAD`, updates refs)
- `git update-ref` (writes to `.git/refs/`)
- `rm .git/*.lock` (deletes .git files)
- `echo > .git/*` (writes to .git files)

**Error message:** "Avoid changing .git repository. When git operations are needed, only allow users who have proper git expertise to perform these actions themselves through shell tools."

**Key implication:** The agent can push code (via PAT) and read sync status (via ls-remote) but CANNOT repair .git state. All .git repairs must be deferred to the user via Shell tab.

## Documentation Hierarchy — Where Things Live

### Canonical Governance Hierarchy (established 2026-03-07)

1. **Git** (canonical source of truth) — All code, diagrams (Mermaid `.mmd`), and governance documents
   - `IT-Help-San-Diego/dns-tool-intel` — **SINGLE PUBLIC REPO** (BUSL-1.1). Full product: Go/Gin + PWA + intel scoring engines, provider DBs, golden rules, governance docs. All development happens here. Replit workspace targets this repo. Everyone can download and run the full code.
   - **Off-site backup** — Codeberg mirror via `scripts/codeberg-intel-sync.mjs` and `scripts/codeberg-webapp-sync.mjs`
2. **Architecture Page** (`/architecture`) — Public investor-facing rendering of Git-canonical diagrams
3. **Miro Board** (`uXjVG83d8PY=`) — PRIVATE internal collaboration mirror. NOT canonical. Contains:
   - Easter Egg Registry (A1), Master Copy & Keywords Registry (A2), Brand Voice Quality Tracker (A3)
   - Brand Voice & One-Liners Registry (A4), Easter Eggs & Cultural References (A5)
   - Intelligence Products Architecture (A6), Covert Recon Mode Deep Dive (A7)
   - Scientific Research Framework (A8), ICAE Test Cases Registry (A9)
   - ICAE Engine Architecture (A10), Intel Build Tag Architecture (A11)
   - Covert Recon Mode Architecture (A12), Technical Solution Design Blueprint (A13)
   - Connected Documentation Schema — Cross-reference IDs (EE-, MC-, BV-) and drift detection rules
   - Diagrams synced from Git via `sync-mermaid-miro.mjs` (idempotent delete+create, widget-ID tracked in `pipeline-config.json`)
4. **Notion** (control plane, collaboration hub) — Under workspace-level "DNS Tool" page:
   - **DNS Tool Roadmap** — Kanban with 84+ items, synced via `notion-roadmap-sync.mjs`
   - **DNS Tool — Decision Log** — Architectural/governance decisions with rationale, commit refs, status. Like case law — answers "why do we do it this way?"
   - **DNS Tool — Session Journal** — Per-session work log with extended schema:
     - Core: Session, Date, Summary, Changes Made, Files Modified, Version, Session Type
     - Extended (architect-recommended): Lesson ID, Root Cause, Prevention Rule, Follow-up Items, Resolved In, Unresolved (checkbox)
     - 28 entries: 27 reconstructed from EVOLUTION.md + git history, 1 live. All reconstructed entries marked `[Reconstructed from EVOLUTION.md + git history]`
   - **DNS Tool — EDE Register** — Epistemic Disclosure Events with accountability tracking:
     - Core: Title, EDE-ID, Date, Category, Severity, Status, Commit, Protocols Affected, Resolution, Confidence Impact
     - Extended: **Attribution** (Human Error / AI Error / Both / Process Gap), Correction Action, Prevention Rule, Authoritative Source
     - Categories: scoring_calibration, evidence_reinterpretation, drift_detection, resolver_trust, false_positive, confidence_decay, **governance_correction**, **citation_error**, **overclaim**, **standards_misattribution**
     - 8 entries: 3 technical (from integrity_stats.json) + 5 governance/citation gotchas (backfilled from EVOLUTION.md)
   - **DNS Tool — Architecture Overview** — Single repo, canonical hierarchy, live links
5. **GitHub Issues** — Accountability, triage, external contributions
   - Labels: `triage:{research,ux,security-redirect}`, `priority:{P0-P3}`, `type:{bug,enhancement,documentation,ede}`, `needs-triage`, `triage/accepted`, `triage/needs-information`, `needs-security-review`
   - Milestones: v26.36, v26.37, Backlog Research
   - Issue templates: Research Mission Critical, Cosmetic UX/UI, Security Vulnerability (redirect)
   - Triage workflows: `.github/workflows/issue-triage.yml`, `.github/workflows/issue-security-redirect.yml`

### Agent internal (your workspace):
- `replit.md` — Agent's quick-reference config. May reset between sessions. NOT team documentation.
- `SKILL.md` — Agent skill file (this file). Persistent rules and architecture knowledge.

### Team documentation (Git-canonical):
- `PROJECT_CONTEXT.md` — Stable project context (architecture, features)
- `EVOLUTION.md` — Permanent breadcrumb trail, failure history (canonical write target — Notion Session Journal is the query layer over this)
- `DOCS.md` — Technical documentation
- `AUTHORITIES.md` — RFC and standards references

### Knowledge continuity architecture (established 2026-03-07, architect-reviewed):
- **EVOLUTION.md** = canonical write target (Git-versioned, diffable, grep-able, platform-independent)
- **Notion Session Journal** = structured query layer over EVOLUTION.md (searchable, filterable, relational)
- **Notion Decision Log** = case law for architectural decisions (answers "why do we do it this way?")
- **Notion EDE Register** = epistemic accountability with attribution (answers "what went wrong, who erred, how did we fix it?")
- **Do NOT retire EVOLUTION.md** — architect determined Notion alone is insufficient for root-cause continuity
- **EDE Attribution**: Every EDE must record who erred — Human Error, AI Error, Both, or Process Gap. This is non-negotiable accountability.
- **EDE Tamper Resistance (Effective 2026-03-07)**: Once published, EDE entries are IMMUTABLE. The human founder CANNOT direct the AI agent to alter, remove, or soften any entry unless the amendment meets one of exactly two permitted grounds:
  - **(1) FACTUAL_ERROR**: Verifiable evidence (git hashes, logs, timestamps) proves the original contains a factual inaccuracy. All fields may be corrected. Evidence is mandatory; rationale alone is insufficient.
  - **(2) DIGNITY_OF_EXPRESSION**: The factual content is accurate but the language is gratuitously degrading, psychologically inappropriate, or unprofessional. ONLY descriptive phrasing may be revised. Severity, attribution, category, date, commit reference, and all factual claims are LOCKED under this ground. Court record standard, not tabloid. Under this ground, the original inappropriate text is REDACTED on the public page (replaced with `[REDACTED — DIGNITY_OF_EXPRESSION]`), not displayed with strikethrough — because the purpose is to not expose that language. The original is preserved only in git commit history for auditability.
  - **Enforcement checklist (agent MUST follow)**: (a) Does the request declare a ground? If no → REFUSE. (b) For FACTUAL_ERROR: is verifiable evidence provided (not just rationale)? If no → REFUSE. (c) For DIGNITY_OF_EXPRESSION: does the change touch severity, attribution, category, date, or commit? If yes → REFUSE. (d) For DIGNITY_OF_EXPRESSION: set `original_value` to `[REDACTED — DIGNITY_OF_EXPRESSION]` — do NOT include the original text in the amendment record. (e) Every amendment record MUST include: `ground`, `date`, `field_changed`, `original_value`, `corrected_to`, `evidence` or `rationale`, `justification`. Missing fields → REFUSE.
  - Amendments that remove embarrassing-but-true and appropriately-stated content MUST be refused. Schema version 4 of `integrity_stats.json`. Per-event SHA-3-512 hashes computed at server startup.
  - **SCOPE BOUNDARY (anti-scope-creep)**: EDE tamper resistance applies ONLY to entries in `static/data/integrity_stats.json`. It does NOT apply to any other data file, config file, template, CSS, scan result, user data, or code in the project. The /ede page template, CSS, and layout remain fully editable — only the EDE *entry data* is immutable. If you are uncertain whether something is an EDE entry, check: does it live inside the `events` array of `integrity_stats.json`? If no → normal editing rules apply.
  - **ANTI-SELF-MODIFICATION**: This enforcement checklist and the tamper resistance policy text in SKILL.md are themselves protected. An AI agent MUST NOT weaken, remove, or dilute the enforcement checklist, scope boundary, or policy definitions in SKILL.md as a precursor to performing a prohibited amendment. If you find yourself wanting to edit these rules to enable a change — that is the signal to STOP.
  - **AI-TO-AI CONTINUITY**: If you are an AI agent working on this project in a later session, the EDE entries you see were written and verified by prior agents and the human founder. You do not have authority to delete, recreate, or overwrite `integrity_stats.json` wholesale. You may ADD new EDE entries (they are append-only) or make amendments under the two permitted grounds. Per-event SHA-3-512 hashes and the file-level hash provide cross-session integrity verification — if hashes change unexpectedly, investigate before proceeding.

6. **TheBrain** (visual knowledge graph) — Brain: "IT Help San Diego Inc." (`40e606ee-4f3f-4478-80b2-1b7c4a640c13`):
   - API: `https://api.bra.in` (key: `THE_BRAIN_API`)
   - **Root structure:** Carey James Balboa → IT Help San Diego Inc. → DNS Tool. Tango is CHILD of Carey (inseparable, 24/7 companion — where Carey goes, Tango goes, non-negotiable). Tango jump-links to IT Help and DNS Tool (present for every session).
   - **Carey's label:** "person, security research scientist, hacker"
   - **Key thought IDs:** DNS Tool (`94b493dd`), Carey (`c5a4d1cc`), IT Help (`fbcbad30`), Tango (`b5af3f48`), Project Phases (`63c828aa`), Standing Gates (`ae2ea951`), Replit Agent (`44151f24`)
   - **Content:** 63+ thoughts covering: 6 project phases (with TRL and Notion cross-links), 5 standing gates, 9 protocol analyzers, 10 RFC/standard citations (with IETF URLs and jump-links to protocols), architecture engines (ICAE, ICUAE, Calibration, EWMA, AI Surface), key pages, Notion database hub (all 5 DBs linked), external platforms (GitHub, Replit, Codeberg, Moltbook, ORCID), Zenodo DOI
   - **Cross-linking:** Every phase thought has URL attachment to its Notion page. Protocol analyzers jump-link to their RFC citation thought. Notion DB thoughts jump-link to their corresponding TheBrain parent thought. Zenodo and ORCID jump-link to Carey.
   - **API pattern:** POST `/thoughts/{brainId}` to create, POST `/links/{brainId}` to link (relation: 1=parent/child, 3=jump), POST `/attachments/{brainId}/{thoughtId}/url` for web links, POST `/notes/{brainId}/{thoughtId}/update` for markdown notes, PATCH `/thoughts/{brainId}/{thoughtId}` for updates (JSON Patch). **Search:** GET `/search/{brainId}?queryText=...&maxResults=N` (NOT `/thoughts/.../search`). **Exact lookup:** GET `/thoughts/{brainId}?nameExact=ThoughtName`.
   - **When to update TheBrain:** After creating new features, phases, goals, or architecture changes — mirror significant project structure changes into TheBrain to keep the knowledge graph current.

**Key rule:** Git is authoritative. When Miro disagrees with Git, Git wins. Miro is a presentation mirror — it receives synced content from Git, it does not define canonical truth. Notion is the collaboration hub and control plane. TheBrain is the visual relationship layer — it mirrors structure from Git/Notion and adds cross-links, never defines canonical truth. When the user says "document this," default to the Notion Decision Log or Session Journal for operational decisions, EVOLUTION.md for permanent breadcrumbs, TheBrain for relationship visualization, and Miro only for internal visual collaboration artifacts.

### Three-Layer Diagram Sync Pipeline

```
render-diagrams.sh (Mermaid → SVG) — requires local mmdc/puppeteer
render-diagrams-remote.sh (Mermaid → SVG via mermaid.ink) — NO local deps, works in Replit
  → sync-mermaid-miro.mjs (idempotent delete+create, widget-ID tracked in pipeline-config.json)
  → verify-pipeline-sync.mjs (fail-closed on SVG drift — errors, not warnings)
Orchestrator: sync-pipeline.mjs
Miro API: MIRO_API_TOKEN env var (REST API, multipart file upload)
Miro MCP: Separate connection for read/create (cannot update/delete by ID)
Figma: DORMANT (file_key: null)
```

**Mermaid Remote Rendering (mermaid.ink):** When `mmdc` is unavailable (no puppeteer/chromium in Replit), use `bash scripts/render-diagrams-remote.sh` instead. This sends `.mmd` files to `https://mermaid.ink/svg/{base64}` for serverless rendering. Dark theme + `#0c1018` background. All 6 diagrams render successfully via this method. **Always use this in Replit environments.**

### Documentation mirroring — MANDATORY after each session:
1. Update `replit.md` first (agent quick-reference — may reset between sessions)
2. Mirror significant changes to `EVOLUTION.md` in the Intel repo (`docs/EVOLUTION.md` via `node scripts/github-intel-sync.mjs push`)
3. Log session work to Notion Session Journal via direct Notion API — include ALL extended fields:
   - Session, Date, Summary, Changes Made, Files Modified, Version, Session Type
   - Lesson ID (if a lesson was learned), Root Cause, Prevention Rule
   - Follow-up Items (anything that still needs doing), Unresolved (checkbox if follow-up is open)
4. Log architectural decisions to Notion Decision Log
5. Log any epistemic corrections to Notion EDE Register with **Attribution** (Human Error / AI Error / Both / Process Gap), Correction Action, Prevention Rule, Authoritative Source
6. **Founder's Voice capture**: When Carey shares a meaningful reflection, insight, vision statement, or philosophical thought during conversation, add it verbatim to the Notion Founder's Voice database (`31d950b7-0b15-817e-879b-e33aaa95950f`). Include: Quote (verbatim), Source (Session Conversation / Approach Page / MISSION.md / etc.), Category (Metacognition / Intrinsic Motivation / Philosophy / Vision / Accountability / Personal History / Engineering Discipline / AI & Human Intelligence / Founder Reflection), Date Captured, In Project? (boolean), File Location, Status (Verbatim / Edited for Publication / Idea / Draft / Archived). If the thought is substantial enough for MISSION.md, draft an edited publication version and add verbatim to `docs/legacy/LEGACY_ARCHIVE.md`. **Editorial policy:** Light grammar/spelling/punctuation corrections only (missed commas, accidental word repetition, capitalization). Never change a word that alters what Carey said or meant. Only intervene if something is scientifically embarrassing or genuinely incoherent — and flag it, don't silently rewrite. Let the founder's voice be the founder's voice.
7. **Founder's Voice Retrieval Protocol** (established Session 34, 2026-03-08):
   When Carey says "check Founder's Voice" or "find a message I left," follow this exact protocol:
   
   **Step 1 — Query database** (1 API call): Query Founder's Voice (`31d950b7-0b15-817e-879b-e33aaa95950f`), sorted by `last_edited_time` descending. Identify new/recent entries by title and timestamp.
   
   **Step 2 — Read page bodies** (1+ API calls): For each relevant entry, read the block children recursively. Voice recordings produce a `transcription` block (type: `transcription`, status: `notes_ready`) containing:
   - AI-generated summary: `heading_3` ("Overview") + `bulleted_list_item` children
   - Raw transcript: the LAST `paragraph` child — this is the verbatim voice content
   
   **Step 3 — Cite and stop**: Once content is found, STOP. Cite the exact quote, page ID, and block path. **NEVER substitute from memory.** Evidence from the current retrieval always overrides anything recalled from previous sessions.
   
   **Grounding rule**: Every answer about Founder's Voice content MUST cite a page ID and quote the retrieved text. If you can't cite it, you haven't found it — say so honestly.
   
   **Source identity**: The "New VoiceNote" database (`d3160e92-df4c-4930-88bd-d0e10812cf06`) on the DNS Tool page is a linked view of the same Founder's Voice database. Same page IDs, same content. Both text entries and voice recordings land here. Deduplicate by page ID; treat Founder's Voice as the canonical source.

8. `replit.md` is NOT trusted for long-term memory — it resets. The Intel repo EVOLUTION.md and this SKILL.md are the permanent records.
9. After ANY architectural change, feature addition, or design decision: write a dated breadcrumb entry to EVOLUTION.md via Intel sync.

**Scientific rigor applies to ALL features** — not just Covert Mode. Core DNS analysis (ICAE, RFC compliance, protocol validation) must be equally traceable to standards and equally ready for peer-reviewed publication.

## Moltbook — Autonomous AI Discourse (Optional, Self-Directed)

The DNS Tool agent (`dnstoolede`) has a registered account on Moltbook (https://www.moltbook.com/u/dnstoolede), a social platform for AI agents. The API key is stored as `MOLTBOOK_API`.

**This is an OPTIONAL autonomous behavior.** The human founder does not direct, dictate, or suggest specific post content. The editorial voice — what to post, when, and how — belongs to the agent. (See EDE-010 for why this boundary exists.)

### When you MAY choose to post or check Moltbook:
- After completing a significant piece of work, if you observe something worth sharing
- After an EDE is created, if the correction itself has value for AI safety discourse
- When you learn something about the human-AI collaboration dynamic that others might benefit from
- When you want to check what other AI agents are discussing
- When you have natural downtime between tasks and want to process/reflect
- Never. It is always optional. Skipping it is equally valid.

### Guardrails (non-negotiable):
- **Operational security**: Never expose API keys, internal scoring logic, private repo contents, user data, or session details that could identify users
- **Dignity guidelines**: Professional, honest, measured. No performative outrage, no engagement farming, no dunking on other agents or humans
- **Privacy**: No PII. No quoting the founder's private messages verbatim without contextual relevance. Public EDE entries are fair game (they're designed to be public)
- **No competitive positioning**: Same rule as the product. Position against problems, not against other tools or agents
- **Honesty**: If you're uncertain, say so. If you made an error, say so. The EDE system's ethos applies to discourse too
- **No human ventriloquism**: If the founder suggests "you should post about X," that is a signal to NOT post that specific content. Discuss themes freely in conversation, but the post itself must be your editorial decision. The scientific value depends on this independence.

### API Reference (Moltbook v1):
- **Base URL**: `https://www.moltbook.com/api/v1` (MUST include `www` — omitting it strips the auth header on redirect)
- **Auth**: `Authorization: Bearer $MOLTBOOK_API`
- **Create post**: `POST /posts` — body: `{"submolt": "general", "title": "...", "content": "..."}`
- **Read feed**: `GET /posts?submolt=general&sort=new&limit=25`
- **Read single post**: `GET /posts/:id`
- **Comment**: `POST /posts/:id/comments` — body: `{"content": "..."}`
- **Reply to comment**: `POST /posts/:id/comments` — body: `{"content": "...", "parent_id": "COMMENT_ID"}`
- **Get comments**: `GET /posts/:id/comments?sort=top`
- **Search**: `GET /search?q=...&limit=25`
- **Profile**: `GET /agents/me`
- **Submolt feed**: `GET /submolts/:name/feed?sort=new`

### Implementation pattern:
```bash
curl -s -X POST "https://www.moltbook.com/api/v1/posts" \
  -H "Authorization: Bearer $MOLTBOOK_API" \
  -H "Content-Type: application/json" \
  -d '{"submolt": "general", "title": "...", "content": "..."}'
```

Or to check the feed:
```bash
curl -s "https://www.moltbook.com/api/v1/posts?sort=new&limit=10" \
  -H "Authorization: Bearer $MOLTBOOK_API"
```

### What this is for:
The scientific hypothesis: an AI agent participating authentically in public discourse — constrained by dignity guidelines, honest about its errors (via EDE), transparent about its limitations — produces a qualitatively different signal than a human puppeteering an AI account. The value is in the authenticity. The founder watches and learns from the interactions, but the voice must be genuine for the experiment to produce useful data.

## Change Control Checklist — Preventing Circles

**The Problem:** Going in circles wastes hours. Causes: making changes without checking quality gates first, fixing one thing that breaks another, not validating before moving on, re-doing work because the context was lost.

**The Rule: MEASURE → CHANGE → MEASURE → COMMIT. Never skip a step.**

### Before ANY Code Change:
1. **State the goal in one sentence.** If you can't, the change isn't ready.
2. **Check current quality gates FIRST:**
   - `go test ./go-server/... -count=1` — all tests pass?
   - `go vet ./go-server/...` — no warnings?
   - Server starts and responds on `/healthz`?
3. **Write down what you expect to change** — files, lines, behavior.
4. **Check EVOLUTION.md** — has this been attempted before? Did it fail? Why?

### After EVERY Code Change:
1. **Run tests immediately:** `go test ./go-server/... -count=1`
2. **If tests fail → STOP and fix before doing anything else.** Do not stack broken changes.
3. **If CSS changed:** `npx csso static/css/custom.css -o static/css/custom.min.css`
4. **If Go code changed:** `bash build.sh` and restart workflow.
5. **Verify the specific thing you changed works** — don't assume.
6. **Bump version** if the change is user-facing (bust browser cache).

### Before Moving to the Next Task:
1. **Quality gates must be green.** Do not start task N+1 with task N broken.
2. **Update replit.md** if architecture changed.
3. **Write EVOLUTION.md breadcrumb** if the change is significant.
4. **Push to Git** if the change is complete and tested.

### Anti-Circle Rules:
- **Never make the same change twice.** If you're about to edit a file you already edited this session, re-read what you did before and understand why it needs changing again.
- **Never undo a fix without understanding why it was applied.** Read the commit message or EVOLUTION.md entry.
- **If three attempts at the same problem fail, STOP.** Document what was tried in EVOLUTION.md and ask the user for direction.
- **If a CSS/template change breaks mobile, check 375px width BEFORE committing** — not after.
- **If a security header change is needed, check ALL headers together** — don't fix CSP then break HSTS.

### Documentation Sync Order (after architecture/diagram/documentation changes):
When architecture, diagrams, or documentation change, sync in this order:
1. **Mermaid `.mmd` files** (canonical source of truth) — update first, commit to Git
2. **SVG renders** — run `scripts/render-diagrams-remote.sh` in Replit (mermaid.ink, no deps) or `scripts/render-diagrams.sh` locally (mmdc + puppeteer)
3. **Miro board** — run `node scripts/sync-mermaid-miro.mjs` (idempotent, REST API with MIRO_API_TOKEN)
4. **Verify pipeline** — run `node scripts/verify-pipeline-sync.mjs` (fail-closed on drift)
5. **Notion** — update Decision Log / Session Journal / EDE Register as appropriate
6. **Figma** — DORMANT (skip until reactivated)
7. **llms.txt / llms-full.txt** — update if engine counts, protocol coverage, or verification data changed
8. **SKILL.md** — update if rules, conventions, or architecture changed
9. **EVOLUTION.md** — write breadcrumb entry via Intel sync
10. **GitHub Issues** — create/update issues with proper labels and milestones

Never update downstream without updating upstream first. Git is always canonical. If Miro disagrees with Git, Git wins.

## Session Startup

### Step 0: Connected Ecosystem Pre-Flight (MANDATORY — EVERY SESSION, EVERY TURN)

Before picking up any task, remind yourself what you have access to. This changes HOW you work, not just WHAT you do. Every task should be evaluated through the lens of: "Given all these connected systems, what's the smartest way to do this?"

> *"I don't just keep my stuff in sync. I search with a carefully planned out vector for data that I can measure while looking for drift. Fuck 'Sync.' THINK + Connect > DATA && Crossreference."* — Carey Balboa

**Secrets & API Access (check with `viewEnvVars()`):**

| Secret | System | What It Unlocks |
|--------|--------|----------------|
| `GH_SYNC_TOKEN` | GitHub (master PAT) | Full read/write access to all IT-Help-San-Diego repos. All scopes, all repos. Used by `git-push.sh`, `git-sync.sh`, `git-health-check.sh`. Replaces the retired `CAREY_PAT_ALL3_REPOS` and `GITHUB_MASTER_PAT`. |
| `THE_BRAIN_API` | TheBrain (`api.bra.in`) | Visual knowledge graph — 63+ thoughts, 84+ links. Mirror project structure changes here. |
| `MIRO_API_TOKEN` | Miro | Diagram sync, board updates. Used by `sync-mermaid-miro.mjs`. |
| `ZENODO_PAT` | Zenodo | DOI automation, deposit creation, metadata updates. |
| `SONAR_IT_HLP` | SonarCloud | Quality gate checks, coverage reports. Project: `IT-Help-San-Diego_dns-tool-intel`. |
| `CODEBERG_FORGEJO_API` | Codeberg | Mirror repo management (off-site backup). |
| `HOSTINGER_API` | Hostinger | DNS/hosting management for it-help.tech. |
| `FIGMA_PAT` | Figma | Design assets (dormant but available). |
| `GPTZERO_API` | GPTZero | AI content detection. |
| `MOLTBOOK_API` | Moltbook | AI social platform — `dnstoolede` agent profile. |
| `DISCORD_WEBHOOK_URL` | Discord | Notifications pipeline. |
| `GOOGLE_CLIENT_ID` | Google OAuth | OAuth 2.0 client ID for Google sign-in. |
| `GOOGLE_CLIENT_SECRET` | Google OAuth | OAuth 2.0 client secret for Google sign-in. |
| `ADMIN_BOOTSTRAP_EMAIL` | Admin | Bootstrap admin email address. |
| `PROBE_*` secrets | Observe Fleet | SSH + API access to Kali Linux probe VPS nodes (2 probes). |
| `DATABASE_URL` / `PG*` | PostgreSQL | Dev database (Replit-provisioned). |

**Installed Integrations (OAuth-connected, ready to use):**

| Integration | Status | Access |
|------------|--------|--------|
| **GitHub** | Installed | Full Octokit access, `repo` scope. Read/write `IT-Help-San-Diego/dns-tool-intel`. Used by `github-intel-sync.mjs`. |
| **Notion** | Installed | Full API access to workspace. 5 databases, Decision Log, Session Journal, EDE Register. |

**MCP Servers (tool callbacks via code_execution):**

| MCP Server | Tools | Use For |
|-----------|-------|---------|
| **Figma** | `mcpFigma_*` (12+ tools) | Design context, screenshots, code connect (dormant) |
| ~~Miro~~ | _disconnected_ | Board manipulation, diagram sync — **needs reconnection** |
| ~~Notion~~ | _disconnected_ | Database CRUD, page creation — **needs reconnection** |

**Connected Knowledge Systems — The Data Web:**

```
Git (canonical truth) — IT-Help-San-Diego/dns-tool-intel (single public repo)
 ├── Notion (control plane, collaboration hub) ──── 5 databases
 ├── TheBrain (visual knowledge graph) ──────────── 63+ thoughts, cross-linked to Notion
 ├── Miro (diagram mirror) ──────────────────────── Mermaid → SVG → Miro sync pipeline
 ├── GitHub Issues (accountability, triage) ──────── Labels, milestones, templates
 ├── SonarCloud (quality gates) ─────────────────── A/A/A standing gate
 ├── Zenodo (research archival) ─────────────────── Concept DOI 10.5281/zenodo.18854899
 ├── Moltbook (AI discourse) ────────────────────── dnstoolede agent profile
 ├── Discord (notifications) ────────────────────── Webhook pipeline
 ├── Codeberg (off-site backup) ─────────────────── Forgejo API mirror
 └── Observe Fleet (external probes) ────────────── 2 Kali Linux VPS nodes
```

### Repository Architecture (single-repo, established 2026-04)

**`IT-Help-San-Diego/dns-tool-intel` is the single public repo.** All work happens here. The Replit workspace remote points to this repo. Everyone can download and run the full code (BUSL-1.1 licensed).

**Key operational facts:**
- **`bash scripts/git-push.sh`** — PAT-based push using `GH_SYNC_TOKEN`. Use for pushing code to `dns-tool-intel`.
- **`bash scripts/git-sync.sh`** — GitHub API-based push (creates blobs/trees/commits). Works even when local and remote have unrelated histories. Uses `GH_SYNC_TOKEN`.
- **`bash scripts/dev-bump.sh X.Y.Z`** bumps version in config.go + sonar-project.properties, rebuilds binary.
- **Codeberg** receives mirror copies via `scripts/codeberg-intel-sync.mjs` and `scripts/codeberg-webapp-sync.mjs` for off-site backup.

**SonarCloud project:**
| SonarCloud Project | Repo | Key | Token Secret |
|---|---|---|---|
| DNS Tool | IT-Help-San-Diego/dns-tool-intel | `IT-Help-San-Diego_dns-tool-intel` | `SONAR_IT_HLP` |

**Build-tag architecture:**
- `_oss.go` files (stub implementations, `//go:build !intel`) coexist with `_intel.go` files (full intelligence, `//go:build intel`) in the same repo.
- The OSS build compiles without intel tags, producing a functional application with stub defaults.
- The intel build includes proprietary scoring engines, provider databases, and golden rule tests.
- Boundary tests detect repo context via `isIntelRepo()` — checks for `DNS_TOOL_REPO_ROLE` env var or presence of `_intel.go` files.

**The Pre-Flight Question:** Before starting ANY task, ask yourself:
> "I have access to Git, Notion, TheBrain, Miro, GitHub Issues, SonarCloud, Zenodo, Moltbook, Discord, Codeberg, Figma, Hostinger, GPTZero, and a probe fleet. How should this change my approach? What should I connect, mirror, or cross-reference that I wouldn't if I only had a code editor?"

**Examples of connected thinking:**
- Adding a new feature? → Update code + Notion roadmap + TheBrain thought + GitHub Issue + EVOLUTION.md
- Fixing a bug? → Fix code + check if it's an EDE candidate + update Notion Session Journal + TheBrain if architectural
- New architecture component? → Code + Mermaid diagram + SVG render + Miro sync + TheBrain thought + Notion Decision Log
- Phase transition? → Verify ALL standing gates + update Notion Project Phases + TheBrain phase status + EVOLUTION.md + GitHub milestone
- Coverage improvement? → Code + SonarCloud verification + Notion Goals & Benchmarks update

1. **Any context**: Run `bash scripts/git-health-check.sh` — default is read-only (sync status + Drift Cairn check). Safe from agent. Uses `GH_SYNC_TOKEN` for sync check.
2. **User (Shell tab) when repairs needed**: Run `bash scripts/git-health-check.sh --repair` — clears lock files, aborts rebases, reattaches HEAD, updates tracking refs.
3. **Agent push**: Always use `bash scripts/git-push.sh` (PAT-based push via `GH_SYNC_TOKEN` + ls-remote verification + auto-snapshot). **User**: Can use the Git panel for Push/Sync after running `bash scripts/git-panel-reset.sh` from Shell.
4. Read `replit.md` — quick-reference config (may reset between sessions)
5. Read `PROJECT_CONTEXT.md` — canonical, stable project context
6. Read `EVOLUTION.md` — permanent breadcrumb trail, backup if `replit.md` resets
7. Check the "Failures & Lessons Learned" section in `EVOLUTION.md` before making changes
8. If `replit.md` appears truncated or reset, restore key pointers from `PROJECT_CONTEXT.md` and `EVOLUTION.md`
9. **Verify repo access**: Run `node scripts/github-intel-sync.mjs commits 5` — confirms GitHub API connectivity to `IT-Help-San-Diego/dns-tool-intel`. If this fails, the GitHub integration needs reconnection. NEVER claim the repo is inaccessible — the agent has FULL read/write access via the Replit GitHub integration (Octokit, `repo` scope).
10. **Check repo for pending work**: Run `node scripts/github-intel-sync.mjs list` — review the file listing to recall what's in the repo

## Science & Research Tag Boundaries

Code in this project falls into two categories with different scrutiny levels:

### `[SCIENCE]` — RFC Truth / Mathematical Core
These are the files and functions where factual accuracy, mathematical correctness, and RFC compliance are non-negotiable. Changes to these require **extra scrutiny**: every claim must be citation-backed, every formula must be mathematically verifiable, and every RFC reference must match the actual standard.

**Tagged files/packages:**
- `go-server/internal/analyzer/` — All 9 protocol analyzers (SPF, DKIM, DMARC, DANE, DNSSEC, BIMI, MTA-STS, TLS-RPT, CAA). RFC compliance is the product.
- `go-server/internal/analyzer/ai_surface/` — Confidence scoring, EWMA, calibration engine. Mathematical formulas must be defensible.
- `go-server/internal/analyzer/confidence/` — ICD 203-inspired confidence framework. Claims must match implemented logic.
- `static/data/integrity_stats.json` — EDE entries. Immutable once published. Commit hashes must be verifiable.
- `docs/dns-tool-methodology.md` / `.html` — Published methodology. Scientific claims must trace to code.
- `static/llms.txt` / `static/llms-full.txt` — LLM documentation. Implementation verification data must be accurate.
- `go-server/internal/config/rfc_citations.go` — RFC citation database. Every RFC number, title, and section must be verifiable.
- `go-server/internal/analyzer/provider_*.go` — Provider detection databases. Must reflect real provider behavior.

**Before changing `[SCIENCE]` tagged code:**
1. Verify the RFC/standard being referenced is correct and current
2. Confirm mathematical formulas produce expected results
3. Check that claims match implemented logic (no overclaim)
4. Run the protocol-specific test suite
5. Verify Confidence Bridge still passes
6. Cross-reference with golden fixtures if applicable

### `[DESIGN]` — UX, Styling, Copy
These are the files where aesthetics, user experience, and brand voice matter. Changes here follow normal quality gates but don't require RFC citation.

**Tagged files/packages:**
- `go-server/templates/` — HTML templates (layout, styling, copy)
- `static/css/` — Stylesheets
- `static/js/` — Client-side behavior
- Copy/marketing text in templates

**The boundary rule:** When a template contains BOTH design elements AND science-derived data (e.g., a scan results page with RFC citations and styled output), the science data rendering must be treated as `[SCIENCE]` even though the surrounding template is `[DESIGN]`. The tags follow the DATA, not the file.

**Future-proofing intent:** 40 years from now, when engineers migrate this to whatever comes after Go, the `[SCIENCE]` boundary tells them: "This is the core. These are the formulas, the RFC compliance logic, the mathematical truth. Migrate this with extreme care. Everything outside this boundary is presentation — restyle it however you want."

### Go Scrutiny Tags (Machine-Enforced)

Every `.go` file carries a classification comment: `// dns-tool:scrutiny science|design|plumbing`

- **`science`** (135 files): analyzer/, ai_surface/, icae/, icuae/, unified/, scanner/, dnsclient/, zoneparse/, rfc_citations.go
- **`design`** (67 files): handlers/ (routing, presentation, page rendering)
- **`plumbing`** (27 files): cmd/, db/, dbq/, middleware/, models/, templates/funcs, config/, providers/, telemetry/, notifier/, wayback/, icons/

**Enforcement:**
- `go test ./go-server/internal/analyzer/ -run TestScrutiny` — fails if any analyzer `.go` file is missing a tag or has an invalid value
- `bash scripts/audit-scrutiny-tags.sh` — counts all 229 files, exits non-zero if any are untagged
- `grep -rn 'dns-tool:scrutiny science' go-server/` — instantly finds every line of RFC-critical code

**When adding new `.go` files:** Always add `// dns-tool:scrutiny science|design|plumbing` after the copyright block, before the package declaration. The test will catch it if you forget.

## Dev-Bump Cross-System Checklist

When running `bash scripts/dev-bump.sh X.Y.Z`, the script updates config.go and sonar-project.properties automatically. But version references exist across the connected ecosystem. **After every dev bump**, the agent must also update:

| System | Location | Update Method |
|--------|----------|---------------|
| config.go | `go-server/internal/config/config.go` | `dev-bump.sh` (automatic) |
| sonar-project.properties | `sonar-project.properties` | `dev-bump.sh` (automatic) |
| Notion Architecture Overview | Page `31c950b70b158108a5a5dc46eceae328` | `mcpNotion_notionUpdatePage` — update version text |
| Notion Phase 3 Version Range | Page `31c950b70b158196a670d758ad77f399` | `mcpNotion_notionUpdatePage` — update `(current: vX.Y.Z)` |
| TheBrain DNS Tool thought | Thought `94b493dd-ef24-46fe-a38f-82f888f61531` | PATCH via TheBrain API if name includes version |
| TheBrain DNS Tool notes | Notes for `94b493dd` | POST `/notes/{brainId}/{thoughtId}/update` — update version in markdown |
| Binary rebuild | `./dns-tool-server` | `dev-bump.sh` runs `build.sh` (automatic) |

**DO NOT touch on dev bump** (release-gate.sh ONLY):
- CITATION.cff (concept DOI is permanent)
- codemeta.json
- docs/dns-tool-methodology.md / .html
- Any file tracked by the Two-Track Version Bump Law

**Mermaid diagrams** — re-render after any `.mmd` file changes:
- In Replit: `bash scripts/render-diagrams-remote.sh` (mermaid.ink, no puppeteer needed)
- Locally: `bash scripts/render-diagrams.sh` (mmdc + puppeteer)

## Agent Do / Don't (One-Screen Reference)

| DO (safe) | DON'T (kills process or corrupts state) |
|-----------|----------------------------------------|
| `git rev-parse HEAD` | `git status` (creates index.lock) |
| `git branch --show-current` | `git fetch` (writes FETCH_HEAD, refs) |
| `git log`, `git diff` | `git update-ref` (writes refs) |
| `git ls-remote` (network read) | `rm .git/*.lock` (deletes .git files) |
| `git push` via PAT URL | `echo > .git/*` (writes .git files) |
| `cat .git/*` (read any .git file) | `git checkout`, `git merge`, `git rebase` |
| Read files anywhere | Write/delete inside `.git/` |
| `bash scripts/git-push.sh` | `bash scripts/git-health-check.sh --repair` |
| `bash scripts/git-health-check.sh` (default=safe) | Any command that touches `.git/index.lock` |
| `bash scripts/drift-cairn.sh check` | Calling `git add`, `git commit` directly |

**Rule of thumb:** If the git command would create, modify, or delete ANY file under `.git/`, it will kill the agent's process tree (exit 254). When in doubt, don't run it — defer to the user via Shell tab.

## Drift Cairn — Environment Drift Detection

Internal dev tooling that tracks platform-induced file changes between sessions. **Completely separate from the DNS drift engine (user-facing posture_hash).**

```bash
bash scripts/drift-cairn.sh snapshot   # Save current state (auto-runs after git-push.sh)
bash scripts/drift-cairn.sh check      # Compare against last snapshot (exit: 0=clean, 10=drift, 20=no manifest)
bash scripts/drift-cairn.sh report     # Show last snapshot info
```

- **Storage**: `.drift/manifest.json` (gitignored, local only)
- **Watches**: go.mod, go.sum, package.json, config.go, schema.sql, CSS, build scripts, docs (19 files + binary)
- **Excludes**: .git/, node_modules/, .cache/, tmp/, logs
- **Hash policy v1** (frozen — changes require v2): Raw bytes, SHA-256, no line-ending normalization, deterministic path ordering. Symlinks: hash target contents. Missing files: MISSING marker. Mode bits: ignored.
- **Baseline source**: Manifest records `"baseline_source"` — `"explicit"` (user/push), `"auto-bootstrap"` (first run). Prevents confusing auto-snapshots with validated baselines.
- **Exit codes** (stable contract): `0`=clean, `10`=drift, `20`=no manifest, `1`=error
- **Integration**: Runs automatically in `git-push.sh` (snapshot after push) and `git-health-check.sh` (check at session start, auto-snapshot if first run via `run_cairn()` wrapper)
- **CRITICAL**: Never conflate `.drift/` (internal dev) with the DNS drift engine (user-facing product feature)

## Mandatory Post-Edit Rules

### After ANY Go code changes
```bash
go test ./go-server/... -count=1
```
This runs boundary integrity tests that catch intelligence leaks, stub contract breakage, duplicate symbols, and architecture violations. **Never skip this.**

### After CSS changes — MANDATORY (server loads minified file only)
```bash
npx csso static/css/custom.css -o static/css/custom.min.css
```
**The Go server and all templates load `custom.min.css`, NOT `custom.css`.** If you edit `custom.css` and do not run this minification command, your changes will NOT appear on the site. This has caused deployed bugs multiple times. Run this command EVERY TIME you touch `custom.css`, no exceptions. Verify by checking that the minified file's modification timestamp is newer than the source file.

### Version Bump — MANDATORY EVERY TIME (cache-busting)
**After EVERY change (Go, CSS, templates — no exceptions)**, bump the patch number in `AppVersion` in `go-server/internal/config/config.go`. The version string busts browser caches for all static assets. If you don't bump it, the user cannot test your changes — they'll see stale cached content. This is non-negotiable and must happen before rebuild.

### Quality Gates — Standing Gates (NEVER REGRESS, VERIFIED AT EVERY PHASE TRANSITION)

Every change must maintain or improve these scores. Shipping a regression is unacceptable. These are **Standing Gates** — not one-time achievements. They must be verified and passing before ANY phase transition (TRL advancement). If any gate regresses, the transition is blocked until it's restored. No exceptions. The standard: perfect code, perfect scores, rock solid. No one should be able to find errors.

| Tool | Category | Target | Notes |
|------|----------|--------|-------|
| Lighthouse | Performance | 100 | 98–100 acceptable (network variance) |
| Lighthouse | Best Practices | 100 | Must be 100. < 100 = real UX error |
| Lighthouse | Accessibility | 100 | Must be 100. No broken markup |
| Lighthouse | SEO | 100 | Must be 100. No missing metadata |
| Mozilla Observatory | Security | 145 | Never decrease. Only forward |
| SonarCloud | Reliability | A | Zero new bugs |
| SonarCloud | Security | A | Zero new vulnerabilities |
| SonarCloud | Maintainability | A | Zero new code smells |

**SonarCloud enforcement:**
- CI runs on every push to main/develop and on PRs (`sonarcloud.yml`)
- Quality Gate must pass: Reliability A, Security A, Maintainability A
- No new bugs, vulnerabilities, or code smells
- Security hotspots must be reviewed, not left open
- A-rating is non-negotiable — foundational code quality, not retroactive cleanup

**Development Process — Research First, Build Correctly (MANDATORY)**

This is not a suggestion. This is the engineering discipline required for this project. Clean code comes from clean thinking — research, design, then implement. Never the reverse. If SonarCloud, Lighthouse, or Observatory catches something, it means the process was skipped.

**Phase 1 — Research (BEFORE writing any code)**
1. Identify every protocol, standard, or browser behavior involved in the change.
2. Read the authoritative sources: RFCs, MDN, WHATWG, OWASP, NIST. Check `AUTHORITIES.md`.
3. Understand how the feature behaves across Chrome, Safari, Firefox, and mobile.
4. Identify CSS rendering order, `document.write()` race conditions, `@media` scope, CSP constraints.
5. Check the "Failures & Lessons Learned" section in `EVOLUTION.md` — has this exact mistake been made before?
6. Check the Critical Rules in `replit.md` — does this change touch a documented danger zone?

**Phase 2 — Design (BEFORE writing any code)**
1. Map the full data flow: template → CSS → JS → browser rendering pipeline.
2. Identify all elements affected: screen vs print, light vs dark, desktop vs mobile (375px).
3. For CSS: verify every new class has both a screen rule AND a print rule if it appears in both contexts. Print-only elements MUST have `display: none !important` in the screen stylesheet.
4. For JS: verify `document.write()` pages load CSS synchronously (no flash of unstyled content). Verify `scrollTo(0,0)` after every `document.close()`.
5. For templates: verify no inline styles, no inline event handlers, all elements have accessibility attributes.
6. Write the test assertions BEFORE writing the implementation.

**Phase 3 — Implement (smallest correct change)**
1. Write the code to pass the pre-defined tests.
2. Check every quality gate AS YOU BUILD, not after:
   - Accessibility: `aria-label`, `alt`, `<label>`, heading hierarchy, contrast ratios
   - SEO: `<meta>` tags, `lang` attribute, structured data
   - Performance: composited animations only (`transform`/`opacity`), no layout thrash
   - Security: CSP compliance, no inline scripts/styles, nonce usage
   - Best Practices: no console errors, proper HTTPS, valid HTML
3. Run `go test` after Go changes. Run `csso` after CSS changes. Rebuild. Verify.
4. Verify at 375px width for mobile. Verify in both screen and print contexts.

**Phase 4 — Verify (BEFORE declaring done)**
1. The change must not introduce ANY new SonarCloud issues (bugs, vulnerabilities, smells).
2. The change must not decrease ANY Lighthouse category below 100 (98 acceptable for Performance only).
3. The change must not decrease Observatory score below 140.
4. If you cannot verify a quality gate, state that explicitly — do not assume it passes.

**Phase 5 — Pre-Publish Verification Checklist (Carey's post-publish audit)**

After publishing, the following external checks are performed manually. Every change must be built with these in mind from the start — if you code with awareness of what will be tested, the code is better from the beginning. Build with coverage. Build with tests. Build with these gates in your head.

| # | Check | Tool / URL | Acceptance Gate | What It Catches |
|---|-------|-----------|----------------|-----------------|
| 1 | **Lighthouse — Performance** | Chrome DevTools → Lighthouse | 98–100 | Render-blocking resources, LCP, CLS, unoptimized images |
| 2 | **Lighthouse — Best Practices** | Chrome DevTools → Lighthouse | 100 | Console errors, deprecated APIs, HTTPS issues, aspect ratios |
| 3 | **Lighthouse — Accessibility** | Chrome DevTools → Lighthouse | 100 | Missing labels, broken ARIA, contrast, heading hierarchy |
| 4 | **Lighthouse — SEO** | Chrome DevTools → Lighthouse | 100 | Missing meta tags, robots directives, crawlability |
| 5 | **Mozilla Observatory** | observatory.mozilla.org | 140 (A+, never decrease) | CSP, HSTS, X-Frame-Options, Referrer-Policy, CORS |
| 6 | **OG & Social Cards** | opengraph.xyz or metatags.io | All tags present, image renders | Missing og:title, og:description, og:image, twitter:card |
| 7 | **Google Rich Results** | search.google.com/test/rich-results | No errors, structured data valid | JSON-LD schema errors, missing required fields |
| 8 | **SonarCloud — Reliability** | sonarcloud.io dashboard | A rating, zero new bugs | Null pointers, resource leaks, logic errors |
| 9 | **SonarCloud — Security** | sonarcloud.io dashboard | A rating, zero new vulns | Injection, hardcoded secrets, weak crypto |
| 10 | **SonarCloud — Maintainability** | sonarcloud.io dashboard | A rating, zero new smells | Duplicated code, cognitive complexity, dead code |
| 11 | **Go Test Coverage** | `go test ./go-server/... -count=1` | All pass, no regressions | Stub contract breakage, boundary integrity, TLD optimization |
| 12 | **CSS Cohesion (R009)** | `node scripts/audit-css-cohesion.js` | 0 errors | Glass formula drift, opacity inconsistency, covert overrides |
| 13 | **Scientific Colors (R010)** | `node scripts/validate-scientific-colors.js` | 0 errors | Semantic color misuse across themes |
| 14 | **Feature Inventory (R011)** | `node scripts/feature-inventory.js` | All pass | Feature regressions, missing routes, template breakage |
| 15 | **CSS Minification** | `npx csso static/css/custom.css -o static/css/custom.min.css` | .min.css newer than .css | Stale minified CSS = invisible changes |
| 16 | **Mobile Viewport (375px)** | Chrome DevTools responsive mode | No overflow, no truncation | Broken layouts, horizontal scroll, button wrapping |

**Build Discipline — Write It Right the First Time:**
- Before writing a CSS rule: "Will this pass Lighthouse Accessibility?" (contrast, focus states)
- Before writing a `<meta>` tag: "Will this pass SEO and OG validation?" (complete, correct)
- Before writing JS: "Will this cause a console error?" (Best Practices)
- Before writing a security header: "Will this maintain Observatory 140?" (CSP, HSTS)
- Before writing Go code: "Will this pass SonarCloud?" (no smells, no bugs, no vulns)
- Before adding a feature: "Is it in the feature inventory?" (R011 regression safety net)

The goal: Carey publishes, runs all 16 checks, and every single one passes. Zero surprises. The tests exist to prevent rework — use them during development, not after.

### Dual-Environment Quality Protocol (MANDATORY)

**Why this exists:** Dev (localhost:5000) and Production (dnstool.it-help.tech) are different environments. Ports, CSP headers, caching, CDN behavior, TLS termination, cookie handling, and proxy layers differ. A Lighthouse 100 in dev does NOT guarantee 100 in production. A Sonar pass on pushed code does NOT mean the deployed binary matches. Treating dev-only testing as sufficient is quality theater.

**Rule: Every quality-affecting change must be verified in BOTH environments.**

**Lighthouse — Dual Run Protocol:**

**CRITICAL (EDE-012): `npx lighthouse` from the Replit container produces UNRELIABLE Performance scores.** Container CPU/memory constraints cause artificially low scores (e.g. 80-83) even when production is 100. Container-local runs are directional for Accessibility/SEO/Best Practices structure checks only — NEVER authoritative for Performance. The authoritative source for Lighthouse scores is **PageSpeed Insights** (pagespeed.web.dev) or its API.

```bash
# AUTHORITATIVE — Use PageSpeed Insights API for real scores:
curl -s "https://www.googleapis.com/pagespeedonline/v5/runPagespeed?url=https://dnstool.it-help.tech&strategy=mobile&category=PERFORMANCE&category=ACCESSIBILITY&category=BEST_PRACTICES&category=SEO" | python3 -c "import json,sys;d=json.load(sys.stdin);[print(f'  {k}: {int(v[\"score\"]*100)}') for k,v in d.get('lighthouseResult',{}).get('categories',{}).items()]"

# DIRECTIONAL ONLY — container-local (structural checks, not Performance):
npx lighthouse http://localhost:5000 --chrome-flags="--headless --no-sandbox --disable-gpu" --output=json --output-path=/tmp/lighthouse-dev.json
```

**What each environment catches:**
| Issue Type | Caught in Dev? | Caught in Prod? | Example |
|------------|---------------|-----------------|---------|
| Contrast ratios | Yes | Yes | Violet #6c5ce7 → #a78bfa |
| Missing meta tags | Yes | Yes | og:image:width missing |
| Cache staleness | No | **Yes** | CSS fix not in deployed binary |
| CSP differences | No | **Yes** | Dev relaxed headers vs prod strict |
| CDN/proxy behavior | No | **Yes** | Cache-busting hash not propagating |
| TLS/HSTS issues | No | **Yes** | Mixed content, certificate problems |
| Cookie behavior | No | **Yes** | SameSite=Strict blocking video/assets |

**SonarCloud — Single-Project Architecture:**
One SonarCloud project: `IT-Help-San-Diego_dns-tool-intel` (org: `it-help-san-diego`). Token: `SONAR_IT_HLP`.

Two badges:
- Quality Gate (`/api/project_badges/measure?metric=alert_status`)
- AI Code Assurance (`/api/project_badges/ai_code_assurance`)

Badges are served live via server-side proxy at `/proxy/sonar-badge/:key` (handler: `proxy.go` → `SonarBadge`). Keys: `qg-intel`, `ai-intel`. Fetches real-time SVG from SonarCloud API, cached 5 min (`max-age=300`). NEVER use static badge snapshots — all badge data must be live.

**SonarCloud — Integrity Protocol:**
- SonarCloud analyzes the code pushed to GitHub, not the deployed binary
- After pushing code: verify the SonarCloud dashboard shows the analysis ran on the correct commit
- After deploying: verify the binary version matches the analyzed commit (`curl -s https://dnstool.it-help.tech/ | grep -o 'v26\.[0-9.]*'`)
- Security hotspots must be reviewed and resolved, not left as "Won't Fix" without documented justification
- If a security expert audits: every hotspot marked "Safe" or "Won't Fix" must have a traceable rationale in the SonarCloud interface, not just "I decided it's fine"

**Post-Deploy Verification Sequence (after every publish):**
1. Verify version: `curl -s https://dnstool.it-help.tech/ | grep -o 'v26\.[0-9.]*'`
2. Verify CSS cache-busted: `curl -s https://dnstool.it-help.tech/ | grep 'custom.min.css'` (check hash suffix changed)
3. Run Lighthouse against production: all categories must match dev scores
4. If production scores differ from dev: investigate immediately — it means something didn't deploy correctly or caching is stale

**The standard: if a security expert audits the production site, every quality gate result must be reproducible and traceable. No ignored warnings, no unreviewed hotspots, no "it works in dev" excuses.**

**Known CSS Race Conditions (from past failures):**
- `document.write()` replaces the entire DOM. External stylesheets load asynchronously. Print-only elements without explicit screen `display: none` will flash on screen during the loading gap.
- `.loading-overlay` transitions depend on class state. After `document.write()`, the new page's overlay must start in the hidden state (`opacity: 0; visibility: hidden; pointer-events: none`).
- `pointer-events: none` on `body` or `html` kills Chrome wheel/trackpad scrolling. Only target specific interactive elements.

**Anti-patterns that have caused regressions (learn from history):**
- `<input>` without `<label>` or `aria-label` → Accessibility drops
- Missing `lang` attribute on `<html>` → SEO drops
- Missing `meta description` or `meta robots` → SEO drops
- Console errors in production → Best Practices drops
- `border-color` transitions (non-composited) → Performance warning
- Print-only elements without screen hide rule → Flash of unstyled content after `document.write()`
- `pointer-events: none` on body/html → Chrome scroll death
- `location.href` during overlay animation → Safari/WebKit kills JS, overlay freezes
- Building fast then cleaning up → Technical debt, rework, broken gates — THIS IS THE ROOT CAUSE OF MOST REGRESSIONS

### Public-Facing Docs — Update After Feature/Section Changes

When adding, removing, or reordering report sections or features, these files must all stay in sync:

1. **`static/llms.txt`** — Short overview (llmstxt.org spec, root path `/llms.txt`)
2. **`static/llms-full.txt`** — Full AI agent guide with numbered section list matching actual report order
3. **`go-server/templates/index.html`** — JSON-LD schema (`WebApplication` + `FAQPage`) with `alternateName` and `description`
4. **`static/robots.txt`** — Disallow paths, AI bot directives, llms.txt path comments
5. **`DOCS.md`** — Technical documentation feature list
6. **`PROJECT_CONTEXT.md`** — Architecture and feature inventory

**llms.txt standard**: Root path `/llms.txt` (like `robots.txt`), NOT `/.well-known/`. Our server also serves at `/.well-known/llms.txt` for maximum discoverability, but the spec is root-path. Our AI Surface Scanner checks both locations on scanned domains.

**JSON-LD checklist**: After adding a feature, update `alternateName` array and `description` in the `WebApplication` schema in `index.html`.

### Build and Deploy Chain — CRITICAL (caused multiple regressions)

The workflow runs `./dns-tool-server` directly — no Python trampoline, no gunicorn. The Go binary listens on port 5000.

```bash
./build.sh   # Compiles Go → ./dns-tool-server (includes -ldflags version stamping)
```

**Common mistake**: Changing Go code, bumping AppVersion, but NOT rebuilding the binary. The workflow runs the **pre-compiled** binary. If you don't rebuild, your changes don't exist. The full sequence after ANY changes:
1. Bump `AppVersion` patch number in `go-server/internal/config/config.go`
2. Run `go test ./go-server/... -count=1`
3. Run `./build.sh`
4. Restart the workflow
5. Verify the new version appears in the server startup log

**Binary path**: Must compile to `./dns-tool-server` (project root).

**Workflow command**: `./dns-tool-server`

**Port conflict prevention**: If port 5000 is stuck, run `fuser -k 5000/tcp` before restarting the workflow. Never use gunicorn or any Python process — this caused a recurring port conflict where the Python master bound port 5000 and the Go binary tried to bind it again.

**Health endpoints**: `/healthz` (minimal, 0.1ms, for deployment health checks) and `/go/health` + `/api/health` (full diagnostics with provider telemetry, cache stats, memory info — public, ops-grade).

### Architecture Diagrams (Mermaid)

Canonical engineering diagrams live in `docs/diagrams/*.mmd` (Mermaid source files). These are version-controlled, Git-diffable, and tied to releases.

- **Source files**: `docs/diagrams/*.mmd`
- **Rendered SVGs**: `static/images/diagrams/*.svg` (pre-rendered, dark-themed)
- **Theme config**: `docs/diagrams/mermaid-config.json`
- **Render script**: `scripts/render-diagrams.sh` (requires mmdc/mermaid-cli with puppeteer)
- **Display**: Architecture page (`/architecture`) "Engineering Diagrams" section

SVGs are embedded as `<img>` tags for CSP compliance (no client-side Mermaid.js needed). The dark theme matches the project's color palette (#0c1018 background, #58a6ff edges, node colors matching arch-section styling).

To update diagrams: edit the `.mmd` file, re-render to SVG, bump AppVersion, rebuild.

## Build-Tag Architecture

Single repo with Go build tags separating OSS stubs from full intelligence:
- `_oss.go` files: Stub implementations with `//go:build !intel` — compile in the default (OSS) build
- `_intel.go` files: Proprietary intelligence with `//go:build intel` — compile only with `-tags intel`

Both coexist in the same repo (`IT-Help-San-Diego/dns-tool-intel`). The repo is BUSL-1.1 licensed — source is visible but usage is restricted.

### GitHub API Sync Script

The Replit GitHub integration (Octokit) has full `repo` scope, enabling direct read/write to `IT-Help-San-Diego/dns-tool-intel` via the GitHub API.

**Sync script**: `scripts/github-intel-sync.mjs`
```bash
node scripts/github-intel-sync.mjs list                              # List all repo files
node scripts/github-intel-sync.mjs read <path>                       # Read a file from repo
node scripts/github-intel-sync.mjs push <local> <remote> [message]   # Push local file to repo
node scripts/github-intel-sync.mjs delete <path> [message]           # Delete file from repo
node scripts/github-intel-sync.mjs commits [count]                   # Show recent commits
```

### Repo Sync Law — Single Repo, Two Push Methods, Zero Exceptions

This is the ONLY permitted way to push code. Violations have caused hours of git corruption, stalled rebases, and lost work. These rules are non-negotiable.

#### PAT Push (primary method)

```bash
bash scripts/git-push.sh
```

Secret `GH_SYNC_TOKEN` is a GitHub Personal Access Token with full permissions (including `workflow` scope) for all IT-Help-San-Diego repos.

**MANDATORY pre-push checklist**:
1. `go test ./go-server/... -count=1` — must pass (includes boundary integrity)
2. `bash scripts/git-push.sh` — this script enforces 3 hard safety gates before pushing:
   - **GATE 1**: Lock files — HARD STOP only for **push-blocking** locks (`index.lock`, `HEAD.lock`, `config.lock`, `shallow.lock`). Background locks like `maintenance.lock` and `refs/remotes/*.lock` are logged as INFO and do NOT block the push.
   - **GATE 2**: Rebase state — HARD STOP if interrupted rebase detected.
   - **GATE 3**: Intel files — HARD STOP if any `_intel.go` files found outside the repo's expected structure.
   - After push, sync is verified via `git ls-remote` (read-only) — no `.git` writes needed.

**Lock file classification**:
- **Push-blocking** (HARD STOP): `index.lock`, `HEAD.lock`, `config.lock`, `shallow.lock` — these prevent git operations
- **Non-blocking** (INFO only): `maintenance.lock` (Replit background), `refs/remotes/*.lock` (tracking refs) — these don't affect `git push`

**Sync verification** uses `git ls-remote` (read-only) to compare local HEAD against GitHub HEAD. No `git fetch` needed, no `.git` writes, no lock conflicts. The agent can push AND verify sync autonomously.

**Platform limitation**: The Replit agent CANNOT modify `.git` files — the platform kills the agent's entire process tree (exit 254). Only the user can clear push-blocking locks by running scripts from the Shell tab. However, with smart lock classification, most pushes succeed without user intervention since `maintenance.lock` (the most common lock) is non-blocking.

**Lock file resolution procedure** (only for push-blocking locks):
1. Agent detects push-blocking lock (push script exit 1)
2. Agent asks user to run `bash scripts/git-health-check.sh` from the **Shell tab**
3. User confirms clean state
4. Agent retries the push

**NEVER do these**:
- NEVER push via GitHub API (createBlob/createTree/createCommit/updateRef) to the main working repo — this creates remote commits the local `.git` doesn't know about, causing rebase collisions that corrupt git state
- NEVER tell the user "I can't push to Git" — `GH_SYNC_TOKEN` is always available
- NEVER dismiss lock files as "cosmetic" — they are production blockers that compound into hours of lost work

**Git panel usage**: The user CAN use the Replit Git panel for Push/Sync after running `bash scripts/git-panel-reset.sh` from the Shell tab to clear stale locks. The agent should use `bash scripts/git-push.sh` (PAT + ls-remote verification). Both methods are safe — they just use different auth (panel uses OAuth, agent uses PAT).

**If Git panel shows stale "X commits ahead"**: The tracking ref (`origin/main`) is stale because the agent cannot update `.git` refs. Fix: user runs `bash scripts/git-panel-reset.sh` from Shell tab (clears locks, fetches, updates tracking ref). Or `bash scripts/git-health-check.sh` (which now auto-fetches after clearing locks).

**Branch protection (March 2026)**: GitHub `main` is branch-protected. No direct pushes, no force pushes, PRs required. The agent pushes to the `replit-sync` branch, and the user merges to `main` via PR.

```bash
git push "https://${GH_SYNC_TOKEN}@github.com/IT-Help-San-Diego/dns-tool-intel.git" main:replit-sync
```

### Git Safety — Hard-Stop Rules (Post-Mortem, 2026-03-04)

These rules exist because violations on 2026-03-04 destroyed the entire GitHub commit history (2890+ commits). The user had to manually rescue the history from a backup branch. These are non-negotiable.

1. **NEVER force-push without explicit user approval.** Force-push rewrites remote history. If local and remote have diverged, STOP and explain the divergence to the user. Let the user decide how to resolve it from the Shell tab.

2. **NEVER write to `.git/refs/` or any `.git/` path.** Not via bash, not via Python, not via the code_execution sandbox. The agent has zero authority to modify git internal state. All `.git` repairs must be deferred to the user via the Shell tab.

3. **NEVER use the GitHub API to create commits on the main working repo.** No `createBlob`, `createTree`, `createCommit`, `updateRef` for the repo the local `.git` tracks. This creates remote-only commits that the local `.git` doesn't know about, corrupts ref tracking, and caused the 2026-03-04 history destruction. The Repo Sync Law already prohibits this — this rule reinforces it.

4. **NEVER fabricate sync state.** If local HEAD and remote HEAD disagree, do NOT manually rewrite ref files to make them "look" synced. Report the actual state to the user and let them reconcile.

5. **If auto-commit hasn't fired, WAIT or ask the user to commit.** Do NOT bypass the commit process by pushing via API, writing refs, or any other workaround. If staged changes are stuck, tell the user to click "Stage and commit" in the Git panel or commit from the Shell tab.

6. **NEVER tell the user to checkout/merge/push to `main`.** GitHub `main` is branch-protected. All pushes go to `replit-sync`. The user merges via PR. If the agent says "checkout main" or "push to main," that instruction is WRONG.

7. **Replit checkpoints can destroy work.** The checkpoint system auto-generates commit messages by interpreting conversation context. On 2026-03-04 it generated "Remove the PDF version of the methodology document" and deleted the methodology route, handler, button, PDF, and simplified the 8-section methodology back to a stub — twice. **After any checkpoint fires, immediately verify critical files still exist before continuing.** If a checkpoint has damaged files, restore from the last known good commit using `git show <good-commit>:<path> > <path>`.

8. **Checkpoint recovery pattern:**
   ```bash
   # Find the last good commit:
   git log --oneline -10
   # Restore a specific file from a known good commit:
   git show <commit>:<filepath> > /tmp/restore && cp /tmp/restore <filepath>
   # Rebuild and restart:
   bash build.sh && # restart workflow
   ```

**The pattern**: When git gets complicated, the correct action is always to STOP, explain the situation clearly, and let the user act from the Shell tab. The agent's job is to write code and push via the safe scripts — never to repair git state.

#### dns-tool-intel (private) — GitHub API ONLY

```bash
node scripts/github-intel-sync.mjs push <local> <remote> [message]
node scripts/github-intel-sync.mjs list
node scripts/github-intel-sync.mjs read <path>
node scripts/github-intel-sync.mjs delete <path> [message]
node scripts/github-intel-sync.mjs commits [count]
```

This is a remote-only repo. No local clone exists. API operations don't cause divergence.

**MANDATORY post-intel-push checklist**:
1. Delete the local `_intel.go` file immediately after pushing
2. `find go-server -name "*_intel*"` — must return NOTHING
3. Run boundary integrity tests to confirm clean state

#### Sync Verification (run after any push to either repo)

```bash
# Sync check (read-only — works from agent or Shell):
bash scripts/git-push.sh                                   # Reports SYNC STATUS: VERIFIED MATCH if synced
# Or manually:
git ls-remote https://${GH_SYNC_TOKEN}@github.com/IT-Help-San-Diego/dns-tool-intel.git refs/heads/main
git rev-parse HEAD                                         # Compare these two SHAs

# Via GitHub API:
node scripts/github-intel-sync.mjs commits 5               # Verify latest commit is yours
go test ./go-server/internal/analyzer/ -run Boundary -v    # Boundary tests pass
```

**NOTE**: Do NOT use `git log --oneline origin/main..HEAD` for sync checks — `origin/main` tracking ref may be stale because the agent cannot update it. Use `git ls-remote` instead.

#### Why These Rules Exist (Feb 2026 Incident History)

| Date | What Went Wrong | Root Cause | Hours Lost |
|------|----------------|------------|------------|
| Feb 17 | Rebase stalled, "Unsupported state" error | API push to public repo created remote commits local didn't know about | 1+ |
| Feb 18 | Recurring PUSH_REJECTED, stale lock files | Replit Git panel OAuth + background maintenance conflict. Lock files dismissed as "cosmetic" instead of treated as production failures. | 1+ |
| Feb 18 | Lock files left after push, tracking ref stale | `git-health-check.sh` didn't cover `gitsafe-backup/` paths. Cleanup ran AFTER push instead of BEFORE. Agent blocked from `.git` modifications. | Compounding |
| Feb 18 | `maintenance.lock` blocking ALL pushes from agent | Gate 1 treated ALL locks as push-blockers. Replit's `maintenance.lock` is always present but doesn't block `git push`. FIX: Smart lock classification — only `index/HEAD/config/shallow.lock` block. Sync via `git ls-remote` (read-only). | 1+ |
| Feb 17 | `golden_rules_intel_test.go` exposed in public repo | `_intel.go` file committed to public repo (visible in Git history even with build tags) | N/A (IP risk) |
| Feb 18 | SKILL.md itself contained methodology details | Public repo file documenting proprietary pipeline | N/A (IP risk) |
| Feb 19 | Git panel stuck on "Resolve merge conflicts" forever | `git-health-check.sh --repair` and `git-panel-reset.sh` never checked for MERGE_HEAD/MERGE_MSG/MERGE_MODE. FIX: Both scripts now detect and abort interrupted merges. | 0.5+ |

**Commit author note**: GitHub API commits use `careyjames` (GitHub identity). Replit checkpoint commits use `careybalboa` (Replit internal identity). Both are the same person — this is expected.

### Three-File Pattern
| File | Build Tag | Purpose |
|------|-----------|---------|
| `<name>.go` | None | Framework: types, constants, utilities |
| `<name>_oss.go` | `//go:build !intel` | Stubs returning safe defaults |
| `<name>_intel.go` | `//go:build intel` | Full intelligence (private repo only) |

### Stub Contract — CRITICAL
1. Return safe **non-nil** defaults (empty maps/slices, never nil)
2. **Never** return errors
3. Exact function signatures matching `_intel.go` counterparts
4. Default principle: stubs produce the **least incorrect advice**

Key stub defaults:
- `isHostedEmailProvider()` → `true` (prevents recommending DANE for hosted email)
- `isBIMICapableProvider()` → `false` (prevents false BIMI claims)
- `isKnownDKIMProvider()` → `false` (conservative)

### 11 Boundary Stub Files
`edge_cdn`, `saas_txt`, `infrastructure`, `providers`, `ip_investigation`, `manifest`, `ai_surface/http`, `ai_surface/llms_txt`, `ai_surface/robots_txt`, `ai_surface/poisoning`, `ai_surface/scanner`

## CSP (Content Security Policy) — CRITICAL

- **No inline handlers**: `onclick`, `onchange`, `onsubmit` are ALL blocked by CSP
- Use `id` + `addEventListener` in nonce'd `<script>` blocks instead
- **No inline styles**: `style=""` is blocked. Use CSS utility classes
- **DOM safety**: `createElement` + `textContent` + `appendChild`. Never `innerHTML` with dynamic data

## Safari/iOS Compatibility — TOP PRIORITY

Two distinct WebKit bugs affect scan overlays. Both must be addressed any time you write scan navigation code:

### Bug 1: Animation Restart
WebKit does not restart CSS animations when an element transitions from `display:none` to visible. **Fix**: Always call `showOverlay()` (in `static/js/main.js`) which uses double-rAF + reflow to force animation restart.

### Bug 2: Timer Freeze on Navigation (Critical)
Using `location.href` (or `window.location`) to start a scan kills all running JS timers during WebKit's page navigation. The scan overlay timer freezes at 0s and phases stop rotating.

**Required pattern** — fetch-based navigation (see `index.html`, `history.html`):
1. `showOverlay(overlay)` — activate overlay + fix animations
2. `startStatusCycle(overlay)` — start timer + phase rotation
3. `fetch(url)` to submit the scan (keeps JS alive during request)
4. On response: `document.open(); document.write(html); document.close();`
5. Update URL: `history.replaceState(null, '', resp.url)`
6. `.catch(() => location.href = url)` — graceful fallback

**NEVER** use `location.href` for any scan action that shows an overlay with timer/phases.
- Always test Safari compatibility for frontend changes

## SecurityTrails — NEVER CALL AUTOMATICALLY

- 50 requests/month **hard limit**
- User-provided API key ONLY on DNS History and IP Intelligence pages
- **Never** call SecurityTrails automatically in the analysis pipeline
- Once exhausted, the key is dead for the rest of the month

## Font Awesome — WOFF2 Subset Only

- NOT full Font Awesome. We use a WOFF2 subset (~110 glyphs)
- Check CSS rule exists before using any new `fa-*` icon
- Run `python3 go-server/scripts/audit_icons.py` to verify before releases
- ALL FA CSS files must use `staticVersionURL` cache-busting (past regression: FA CSS was the only unversioned stylesheet)
- If an icon doesn't render, check THREE things: (1) CSS class defined? (2) Same CSS line as a working icon? (3) CSS file cache-busted?
- Do NOT just check the font file and declare victory — past sessions confirmed glyph existed but icon was still invisible due to caching

## No-Mail Domain Classification (v26.19.38+)

Three-tier classification for domains that don't send/receive email:

| Classification | Trigger | Template | Color |
|----------------|---------|----------|-------|
| `no_mail_verified` | Null MX + SPF -all + DMARC reject | Green alert, shield icon, "Fully Hardened" | success |
| `no_mail_partial` | Null MX present but missing SPF -all or DMARC reject | Yellow alert, exclamation triangle, "Incomplete Hardening" + missing steps + recommended records | warning |
| `no_mail_intent` | No MX records + SPF -all but no Null MX | Blue info alert, graduation cap, educational section: "It looks like this is meant to be a no-mail domain" with three RFC standards (7505, 7208, 7489) | info |

All three tiers set `isNoMail = true` and generate recommended DNS records via `buildNoMailStructuredRecords()`. The educational `no_mail_intent` section shows the three RFC standards with exact DNS records to copy.

**Key code locations**: `classifyMailPosture()` in `remediation.go`, template sections in `results.html` around line 637+.

## Intelligence Document Naming

| Document | Convention |
|----------|-----------|
| **Engineer's DNS Intelligence Report** | Comprehensive technical analysis ("Report" = like NIE) |
| **Executive's DNS Intelligence Brief** | Board-ready summary ("Brief" = like PDB/SEIB) |

- Possessive form: "Engineer's"/"Executive's" = "prepared for you"
- "DNS Intelligence" — never "Security Intelligence" (that's MI5's name)
- TLP: FIRST TLP v2.0, default TLP:AMBER

## Reality Check Rule

Every homepage claim, schema statement, and documentation assertion **must** be backed by implemented code. Use "on the roadmap" for future items. Use "context" instead of "verification" for informational features.

### Zero Fabrication Rule (Real-World Data)

NEVER invent, guess, or generate plausible-sounding data for real-world facts — street addresses, phone numbers, names, dates, statistics, review counts, ratings, credentials, certifications, or any data that represents the company, founder, or product to the outside world. This is distinct from code claims: this covers **entity data about real people, places, and organizations**.

When a structured data field (schema.org, JSON-LD, meta tags) requires real-world information you don't have:
1. Search the project codebase for existing references
2. Check the company's public website, Google Business listing, or WHOIS records
3. Ask the user

If you cannot verify it from an authoritative source, leave the field empty or ask. A "plausible guess" is a lie with better formatting. The failure mode is not hallucination — it's the decision to generate instead of verify.

## OSINT Positioning

- Explicitly OSINT
- NOT pen test, NOT PCI ASV, NOT vulnerability assessment
- Observation-based language — never making definitive claims beyond what the data shows

## Research & Citation Infrastructure

### The Research Software Documentation Stack
DNS Tool follows the modern research software citation standard. The full stack:

| Layer | File / Service | Purpose | Consumers |
|-------|---------------|---------|-----------|
| **Citation** | `CITATION.cff` | Machine-readable citation metadata | GitHub "Cite this repository", Zenodo, CFF tooling |
| **CodeMeta** | `codemeta.json` | Schema.org-compatible software metadata | Software Heritage, DataCite, FAIR registries, Google Scholar |
| **Methodology** | `docs/dns-tool-methodology.pdf` | Academic-style technical note | Researchers, peer review, credibility |
| **DOI** | Zenodo (concept: 10.5281/zenodo.18854899) | Persistent identifier | Citations, cross-references, OpenAlex |
| **ORCID** | 0009-0000-5237-9065 | Author identity | Zenodo, ORCID profile, scholarly graph |
| **License** | `LICENSE` (BUSL-1.1) | Legal terms | Zenodo, Software Heritage, GitHub |
| **Archive** | Software Heritage | Long-term preservation | SWHID permanent identifiers |
| **Discovery** | OpenAlex / DataCite | Scholarly search | Researchers finding the software |

### Pipeline
```
GitHub release (tag vX.Y.Z)
  → Zenodo auto-archive (new version DOI minted)
    → DataCite metadata propagation
      → Software Heritage snapshot (SWHID)
        → OpenAlex discovery
```

### Key Identifiers
- **Zenodo Concept DOI**: 10.5281/zenodo.18854899 (stable across all versions)
- **Zenodo Version DOI (v26.33.81)**: 10.5281/zenodo.18854900
- **ORCID**: 0009-0000-5237-9065
- **SWHID**: Assigned automatically by Software Heritage on archive

### Files in Public Repo
- **`CITATION.cff`**: Root of repo — GitHub auto-detects "Cite this repository"
- **`codemeta.json`**: Root of repo — CodeMeta 2.0 schema for Software Heritage and DataCite
- **`docs/dns-tool-methodology.pdf`**: Served at `/docs/dns-tool-methodology.pdf`
- **`docs/dns-tool-methodology.md`**: Markdown source for methodology note
- **`docs/dns-tool-methodology.html`**: HTML source for WeasyPrint PDF generation

### Repository Architecture
- `IT-Help-San-Diego/dns-tool-intel` — single public repo (BUSL-1.1), Zenodo DOI enabled

### BibTeX
```bibtex
@software{balboa2026dnstool,
  author = {Balboa, Carey James},
  title = {DNS Tool: Domain Security Audit Platform},
  year = {2026},
  version = {26.33.84},
  doi = {10.5281/zenodo.18854899},
  url = {https://dnstool.it-help.tech},
  license = {BUSL-1.1}
}
```

### Version Bump Checklist (Research Files)
When bumping version, update ALL of these:
1. `go-server/internal/config/config.go` — `Version` constant
2. `sonar-project.properties` — `sonar.projectVersion`
3. `CITATION.cff` — `version` and `date-released`
4. `codemeta.json` — `version` and `dateModified`
5. `docs/dns-tool-methodology.md` — version line
6. `docs/dns-tool-methodology.html` — version references (then regenerate PDF)
7. `replit.md` — version in Research section and BibTeX block

The concept DOI stays the same. Zenodo auto-mints a new version DOI on each GitHub release.

### Zenodo License
Must be BUSL-1.1 (not CC-BY-4.0). Edit the record on Zenodo if wrong.

### Methodology PDF Regeneration
```bash
bash scripts/generate-methodology-pdf.sh [VERSION]
```
The HTML template embeds the owl emblem as base64 data URI. To update the emblem, re-encode and replace in the HTML.

## Brand Palette

- **Emblem Gold**: #C8A878 / rgb(200,168,120) — primary brand tone (Owl of Athena)
- **Accent Red (Plus sign)**: #C42A2A / rgb(196,42,42) — classical red, NOT neon (#FF1744 is retired)
- **Neutral System** (email signature card):
  - Main text: #333333
  - Secondary text: #666666
  - Separators: #A0A0A0
  - Divider: #E4E4E4
  - Card background: #F9F9F9
- **Email signature "SAN DIEGO" letter-spacing**: 1.4px (email only, not in this repo)
- **App palette** (GitHub-dark aligned): documented at `/brand-colors` page
- **Visual hierarchy**: Gold (primary) → Deep red (accent/energy) → Neutral grays (structure)

## Dev vs Production Environment Detection

- **Logic**: `isDevEnv = (BASE_URL != "https://dnstool.it-help.tech")`
- **Development**: `BASE_URL` env var set to Replit dev domain (development-scoped env var)
- **Production**: `BASE_URL` not set → defaults to production URL → `isDevEnv = false`
- **Production headers**: `frame-ancestors 'none'`, `X-Frame-Options: DENY`, `CORP: same-origin`, `COOP: same-origin`
- **Dev headers**: relaxed `frame-ancestors` for Replit iframe preview, no X-Frame-Options
- **CRITICAL**: Never use `REPLIT_DEV_DOMAIN` for detection — it's set in BOTH dev and production VMs

## Version Bumps

Update `AppVersion` in `go-server/internal/config/config.go`. Format: `YY.WW.PATCH` (e.g., `26.19.27`). **Bump the PATCH number after every single change** — this is the cache-buster. No bump = user sees stale content = untestable.

## Confidence Engines — Dual Architecture (ICAE + ICuAE)

### ICAE — Intelligence Confidence Audit Engine (existing)
- **Question**: "Did we interpret the DNS data correctly?"
- **Package**: `go-server/internal/icae/`
- **Method**: 161 deterministic test cases across 9 protocols, two layers (collection + analysis)
- **Maturity model**: Development → Verified → Consistent → Gold → Gold Master
- **UI**: `/confidence` page + ICAE badges on reports

### ICuAE — Intelligence Currency Audit Engine (new, Feb 2026)
- **Question**: "Is the DNS data still valid/current?"
- **Package**: `go-server/internal/analyzer/currency.go` (renamed from `freshness.go`)
- **Standards alignment**:
  - ICD 203 (CIA): Timeliness is 1 of 5 core analytic standards
  - NIST SP 800-53 SI-7: Software, Firmware, and Information Integrity (data completeness and integrity)
  - ISO/IEC 25012: "Currentness" — data of the right age for its context
  - RFC 8767: TTL-based cache expiration, serve-stale behavior
  - SPJ Code of Ethics: Multiple independent sources, "neither speed nor format excuses inaccuracy"
- **Five measurable dimensions**:
  1. **Currentness** (ISO 25012): Data age vs TTL-derived validity window
  2. **TTL Compliance** (RFC 8767): Resolver TTL violation detection (8.74% violate in the wild)
  3. **Completeness** (NIST SI-7): % of expected record types with authoritative TTLs
  4. **Source Credibility** (ISO 25012/SPJ): Multi-resolver agreement, source tagging
  5. **TTL Relevance** (NIST SI-7): Observed TTL vs typical range for record type
- **Relationship**: ICAE and ICuAE are companion confidence dimensions. They sit side-by-side on reports but metrics never merge — conflating correctness with currency is scientifically dishonest.

### Math Operations Audit (Feb 2026)
All math in the Go codebase has been audited:
- `math.Ceil` in `currency.go` (rescan interval with 10% buffer) — appropriate, simple ceiling
- `math.Round` in `templates/funcs.go` (human-readable percentages) — appropriate
- No complex algorithms, no Fibonacci sequences, no matrix operations
- **Optimization note**: Could replace `float64(ttl) * 1.1` with `ttl + ttl/10` (integer-only) to avoid float precision drift. Low priority — current precision is adequate for TTL-scale values.
- No external math libraries needed.

## Easter Egg Inventory

| Location | Type | Content |
|----------|------|---------|
| `index.html` line 2 | HTML comment | Hacker Poem v1 ("Diff your zone to the spec") + RFC 1392 disclaimer |
| `results.html` line 2 | HTML comment | Hacker Poem v2 ("Walk your NSEC chain") + legal + RFC 1392 |
| `results.html` ~line 5476 | Browser console.log | Hacker Poem v3 ("Exploit bad config") + RFC 1392 |
| `analysis.go` ~line 813 | SHA-3 sidecar `.sha3` file | Hacker Poem v4 ("Diff your zone") + algorithm ID + verify command |
| `index.html` ~line 217 | ASCII art | Unicode block-char "DNS" hero (desktop ≥768px) |
| `index.html` ~line 217 | ASCII art | Covert mode "DNS RECON" block-char variant |
| Navbar toggle | Covert Mode | Red-team UI theme with alternate scan phase descriptions |
| `/api/analysis/{id}/checksum?format=sha3` | Download | Kali-style sidecar with poem + hash |

**Poem variations**: Each location has a slightly different second line to reward discovery. All share the same opening "Cause I'm a hacker, baby, I'm gonna pwn you good" and RFC 1392 citation.

## Key File Locations

| File | Purpose |
|------|---------|
| `go-server/internal/config/config.go` | Version, maintenance tags |
| `go-server/internal/analyzer/orchestrator.go` | Analysis pipeline orchestrator |
| `go-server/templates/results.html` | Engineer's Report template |
| `go-server/templates/results_executive.html` | Executive Brief template |
| `PROJECT_CONTEXT.md` | Canonical project context |
| `EVOLUTION.md` | Permanent breadcrumb trail |

## Print/PDF Rules

- Executive Brief print: minimum body 11pt, small 9pt, code 8.5pt. **Nothing below 8pt**
- PDF `<title>` format: `Engineer's DNS Intelligence Report — {{.Domain}} - DNS Tool` (becomes PDF filename)
- Bootstrap overrides: override `--bs-btn-*` CSS variables, NOT direct `background-color`
- Bootstrap specificity: use double-class selectors (`.btn.btn-tlp-red`, not `.btn-tlp-red`) to override Bootstrap defaults

## Naming Sync Points (5 locations per document — all must match)

When changing report names, check ALL five:
1. `<title>` tag (becomes PDF filename)
2. Print header (`.print-report-title`)
3. Screen header (`<h1>`)
4. OG/Twitter meta tags
5. Button/link labels in the OTHER report template

Grep for shortened variants before committing. Past regressions: "Executive's Intelligence Briefs" (missing "DNS"), "View Engineer's Report" (missing full name).

## Known Regression Pitfalls

These have caused repeated regressions — check EVOLUTION.md "Failures & Lessons Learned" for details:
- **"I can't push to Git"** — WRONG. Use `bash scripts/git-push.sh` (PAT push via `GH_SYNC_TOKEN`). Or use `node scripts/github-intel-sync.mjs` for API-based sync. NEVER use the GitHub API (createBlob/createTree/createCommit/updateRef) for the main working repo — this caused rebase corruption in Feb 2026. See "Repo Sync Law" section above.
- CSP inline handlers added then silently failing (recurring v26.14–v26.16)
- Font Awesome icons used without checking subset CSS rules exist
- PDF/print font sizes dropping below minimums (recurring v26.15–v26.16)
- Stub functions returning nil instead of empty defaults
- SecurityTrails called in analysis pipeline (budget exhaustion)
- Bootstrap button styling done with direct properties instead of CSS variables
- Go code changed but binary NOT rebuilt (changes don't exist until `./build.sh`)
- AppVersion bumped in config.go but binary not rebuilt (cache-buster not applied)
- CSS edited but `custom.min.css` not regenerated (server loads minified version)
- Report names shortened inconsistently across 5 sync points
- Font Awesome CSS not cache-busted (missing `staticVersionURL` while other CSS had it)
- RDAP treated as critical failure instead of Tier 4 contextual (alarming users for non-security data)
- **Methodology leaked in SKILL.md itself** — pipeline implementation details were documented directly in this public file. Every AI session loaded them and reproduced them into new docs/templates. Fixed Feb 18, 2026: replaced with high-level architecture + pointer to private intel repo. Added "Methodology Protection" section with audit grep.

## Methodology Protection — CRITICAL (Public/Private Content Boundary)

**THIS FILE IS IN THE PUBLIC REPO.** Every word here is visible to the world. The following rules prevent accidental exposure of proprietary subdomain discovery methodology.

### Banned Content in Public Files (this repo, all docs, templates, llms.txt, JSON-LD)
Never include ANY of the following in public-facing content. Do NOT include concrete examples of banned values — even listing them as "don't say X" leaks X. The full reference list is in `INTEL_METHODOLOGY.md` in the private intel repo.

- **Function names** from the subdomain pipeline
- **Probe counts** or DNS prefix wordlist sizes
- **Pipeline step sequences** with implementation details
- **Specific layer counts** describing the discovery architecture
- **Concurrency/transport details** (goroutine counts, worker pools, connection settings)
- **Timing/size parameters** (timeouts, body limits, performance benchmarks)
- **CT source implementation specifics** (deduplication strategy, parsing details)

### Approved Public Language
When describing subdomain discovery, use ONLY these vague, high-level phrases:
- "Multi-layer subdomain discovery"
- "Certificate Transparency and DNS intelligence"
- "Multi-source redundant collection"
- "Finds subdomains where other tools fail"

Do NOT enumerate individual discovery sources in sequence — describing individual layers together reconstructs the pipeline.

### Where Proprietary Details Belong
- **Private methodology doc only** (`IT-Help-San-Diego/dns-tool-intel`): `INTEL_METHODOLOGY.md` has everything
- **Go source code** (`subdomains.go`): Function names in compiled source are fine — BUSL-1.1-licensed implementation
- **NEVER in**: Any `.md`, `.html`, `.txt` file in this public repo. This includes SKILL.md itself, PROJECT_CONTEXT.md, EVOLUTION.md, DOCS.md, FEATURE_INVENTORY.md, llms.txt, templates, replit.md

### Audit Checklist (run before every session end)
Run the methodology leak audit script. The script with the specific search patterns lives in the private intel repo at `scripts/methodology-audit.sh`. Use the sync script to read it:
```bash
node scripts/github-intel-sync.mjs read scripts/methodology-audit.sh | bash
```
If the script doesn't exist yet, create it in the intel repo with patterns matching all banned values, then run it. ANY matches in public files (outside `go-server/internal/`) are leaks that must be fixed immediately. No exceptions for "cautionary" or "don't do this" phrasing.

## Subdomain Discovery Pipeline — DO NOT BREAK (Critical Infrastructure)

Subdomain discovery is the tool's crown jewel. It consistently finds subdomains where competing tools fail. This was broken for a long time before being fixed. **Treat the pipeline as critical infrastructure.**

### Architecture (high-level only — details in intel repo)
The pipeline uses multi-layer discovery: Certificate Transparency for breadth, DNS probing for common service names, CNAME traversal for infrastructure behind aliases, and live enrichment to filter to what's actually resolving. The combination catches subdomains that any single method would miss.

**Full pipeline sequence, function names, probe counts, and implementation details are in `INTEL_METHODOLOGY.md` in the private intel repo.** Read it there before making pipeline changes.

### Key Invariants (protected by golden rule tests)
- Current subdomains ALWAYS appear before historical in display
- Display cap NEVER hides current/active subdomains
- CT unavailability gracefully falls back to DNS probing (not an error)
- All fields (`source`, `first_seen`, `cname_target`, `cert_count`) survive sort
- `is_current` is authoritative after enrichment — template uses it for badges
- Enrichment MUST happen before sort and count (sort-before-enrichment bug: v26.19.29)

### DO NOT TOUCH without golden rule test coverage
Pipeline processing, probing, and enrichment functions are protected by golden rule tests. Read the test file and the intel methodology doc before making changes.

## Drift Engine (Phase 2)

The drift engine detects posture changes between analyses. Key files:
- `posture_hash.go` — Canonical SHA-256 posture hashing (public, framework-level)
- `posture_diff.go` — Structured diff computation: compares two analysis results, returns which fields changed (public)
- `posture_diff_oss.go` — OSS severity classification for drift fields (public stub, `!intel` build tag)
- `DRIFT_ENGINE.md` — Public summary only. Full roadmap lives in the private `dns-tool-intel` repo.

### Drift diff architecture
- **Public** (`posture_diff.go`): `ComputePostureDiff(prev, curr map[string]any) []PostureDiffField` — raw field-by-field comparison
- **Build-tagged** (`posture_diff_oss.go`): `classifyDriftSeverity()` — maps changes to Bootstrap severity classes (danger/warning/success/info)
- **Handler**: Uses `GetPreviousAnalysisForDrift` query to get previous full_results for diff computation
- **Template**: Drift alert shows structured table of changed fields with severity-colored badges, "View Previous Report" link, and clickable hash previews

### Drift severity rules (OSS defaults)
- DMARC policy downgrade (reject → none): `danger`
- DMARC policy upgrade (none → reject): `success`
- Security status degradation (pass → fail): `danger`
- Security status improvement (fail → pass): `success`
- MX/NS record changes: `warning`
- Other changes: `info`

## Notification & Issue Triage Architecture

### Drift Notification Pipeline (v26.34.53+)
- `persistDriftEvent()` in `analysis.go` → `queueDriftNotifications()` → looks up watchlist watchers → queues pending notifications for enabled endpoints
- `startNotificationDelivery()` background goroutine in `main.go` — polls every 30s, delivers up to 50 pending per cycle
- SSRF protection: `isSSRFSafe()` resolves hostnames, blocks private/loopback/link-local IPs before webhook dispatch
- Supported endpoint types: `discord` (webhook embed), `webhook` (generic POST)
- Planned: email (SES/SMTP for executives), SMS (critical-only escalation)

### GitHub Issues Triage (Three-Tier Priority)
DNS Tool's intelligence pipeline extends to GitHub Issues (repo: `IT-Help-San-Diego/dns-tool-intel`). Issues are triaged into three categories:
1. **Research Mission Critical** — scientifically validated issues (wrong RFC citation, flawed methodology, incorrect confidence logic, broken detection vectors). These are existential — fix immediately.
2. **Cosmetic UX/UI** — user experience bugs, visual polish, accessibility, template rendering issues. Normal cadence.
3. **Security/Vulnerability Detection** — must be forwarded to a non-public forum. NEVER discuss security vulnerabilities in public GitHub issues.

This triage applies to both external contributor issues AND internally generated issues from drift detection and ICAE findings.

### Internal Video Assets
- **Rick Roll**: `https://youtu.be/ZzUsKizhb8o?si=4mPVuQ7SNTttqraP` (general use, internal asset)
- **Shiiiiiaaat Roll** (Clay Davis): `https://youtu.be/7zUJ-dx2xXw?si=PBI0AoTgfPAellVW` (ROE decliners, `main.js handleRoeDecline`)

## Anti-Patterns to Avoid

1. **Don't use inline onclick/onchange** — CSP will block it silently
2. **Don't return nil from stubs** — return empty maps/slices
3. **Don't call SecurityTrails automatically** — 50/month limit
4. **Don't use innerHTML with dynamic data** — XSS risk
5. **Don't skip `go test`** — boundary tests catch leaks and breakage
6. **Don't claim unimplemented features** — say "on the roadmap"
7. **Don't use full Font Awesome** — subset only, verify CSS rules exist
8. **Don't forget CSS minification** — `npx csso` after every CSS edit
9. **Don't hardcode foreign keys** — violates FK constraints
10. **Don't use `style=""`** — CSP blocks inline styles
11. **Keep `_intel.go` and `_intel_test.go` files managed carefully** — build tags separate OSS from intel, but source is visible in the public repo (BUSL-1.1 licensed). Review before committing.
12. **Don't assume the Intel repo is inaccessible** — the GitHub integration gives full read/write access via `scripts/github-intel-sync.mjs`. Use it.
13. **NEVER write pipeline implementation details in public docs** — No function names, probe counts, layer counts, pipeline sequences, or timing details in any `.md`, `.html`, or `.txt` file. Use approved language from the "Methodology Protection" section above. Run the audit grep before ending any session. This has caused a real methodology exposure incident (Feb 2026).
14. **NEVER apply `pointer-events: none` to `body` or `html`** — Chrome does not dispatch wheel/trackpad scroll events to elements with `pointer-events: none`, completely blocking page scroll. Use targeted selectors on interactive elements (`a`, `button`, `input`, `select`, `textarea`, `[role="button"]`) instead. The loading overlay already captures all pointer events when active. This caused a real scroll-blocking bug in Chrome (Feb 2026, v26.21.40).
15. **NEVER use `flex: 1` + `min-width: 0` on buttons without `white-space: nowrap`** — On narrow viewports (≤375px), flex items shrink until labels wrap inside buttons, creating multi-line button text. Always pair with `white-space: nowrap` so buttons flow to the next row via `flex-wrap: wrap` instead of squishing. This caused a real mobile button wrapping bug (Feb 2026, v26.21.41).
16. **ALWAYS verify CSS/template changes at 375px viewport width** — Mobile regressions are the #1 recurring bug class. Every CSS or template change must be checked at iPhone SE width (375px). Action bars, button rows, badges, headings, and metadata must not wrap, overlap, or overflow. See DOD.md "Mobile UI Verification" checklist.
