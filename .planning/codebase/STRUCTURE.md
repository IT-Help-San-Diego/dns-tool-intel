# DNS Tool — File Structure Map

## Root Directory
```
/
├── dns-tool-server           # Compiled binary
├── build.sh                  # Go build script with ldflags
├── go.mod / go.sum           # Go module dependencies
├── package.json              # NPM dependencies (testing, scripts)
├── pyproject.toml / uv.lock  # Python dependencies
├── sonar-project.properties  # SonarQube config
├── CITATION.cff              # Academic citation metadata
├── codemeta.json             # CodeMeta software metadata
├── LICENSE                   # BUSL-1.1
├── replit.md                 # Replit agent context document
└── .replit                   # Replit workspace config
```

## Go Server (`go-server/`)
```
go-server/
├── cmd/server/main.go        # Entry point (router, DI, startup)
├── internal/
│   ├── analyzer/             # DNS analysis (SPF, DKIM, DMARC, etc.)
│   ├── config/config.go      # Version, env var loading
│   ├── db/db.go              # PostgreSQL connection pool
│   ├── dbq/                  # SQLC-generated queries
│   ├── dnsclient/            # Multi-resolver DNS client
│   ├── handlers/             # HTTP handlers
│   ├── icae/                 # Confidence audit engine
│   ├── icuae/                # Currency assurance engine
│   ├── middleware/           # Security, auth, rate limiting
│   ├── scanner/              # CISA feed, vulnerability scanning
│   └── templates/funcs.go    # Template helpers (SRI, URLs)
├── db/migrations/            # SQL migration files
└── sqlc.yaml                 # SQLC config
```

## Templates (`go-server/templates/`)
```
go-server/templates/
├── _head.html, _nav.html, _footer.html, _flash.html  # Partials
├── index.html               # Landing page
├── results.html             # Engineer's Report
├── results_executive.html   # Executive's Report
├── results_covert.html      # Covert Recon Mode
├── approach.html            # Methodology
├── confidence.html          # Confidence framework
├── dossier.html, history.html, stats.html
├── admin_ops.html, admin_probes.html, admin_users.html
├── zone.html, badge_embed.html, toolkit.html
└── (others)
```

## Static Assets (`static/`)
```
static/
├── css/custom.css            # Source CSS
├── css/custom.min.css        # Minified (CSSO)
├── css/fontawesome-subset.min.css
├── js/main.js                # Source JS
├── js/main.min.js            # Minified (Terser)
├── js/foundation.js
├── images/owl-of-athena*.{png,webp}  # Brand logo variants
├── images/diagrams/          # Architecture diagrams
├── vendor/katex/             # Self-hosted KaTeX
├── webfonts/                 # FontAwesome WOFF2
├── bimi-logo.svg             # BIMI brand indicator
├── favicon.svg               # Vector favicon
├── sw.js                     # Service worker
├── manifest.json             # PWA manifest
├── robots.txt, llms.txt, llms-full.txt
└── .well-known/              # Security.txt
```

## Scripts (`scripts/`)
```
scripts/
├── build.sh → ../build.sh    # (symlink or reference)
├── audit-css-cohesion.js      # R009: CSS quality gate
├── validate-scientific-colors.js  # R010: Color validation
├── feature-inventory.js       # R011: Feature tracking
├── refresh-golden-fixtures.sh # Update golden test data
├── notion-roadmap-sync.mjs    # Notion API sync
├── github-intel-sync.mjs      # GitHub intel sync
├── codeberg-intel-sync.mjs    # Codeberg sync
├── seed-dev-db.sql            # Development database seeding
├── generate-og-images.sh      # OG image generation
└── (others)
```

## Tests
```
tests/
├── golden_fixtures/           # Real domain analysis snapshots (JSON)
├── e2e/                       # Playwright E2E tests
└── (in-package tests)         # *_test.go files alongside source
```

## Multi-Repo Map
```
careyjames/dns-tool-web     [PUBLIC]   ← This Replit workspace
careyjames/dns-tool-intel   [PRIVATE]  ← IP modules, internal docs
careyjames/dns-tool         [ARCHIVED] ← Legacy CLI
careyjames/dns-tool-cli     [PUBLIC]   ← Future hacker CLI
```
