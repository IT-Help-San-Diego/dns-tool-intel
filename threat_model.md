# Threat Model

## Project Overview

DNS Tool is a publicly deployed Go/Gin web application for DNS and email-security analysis. It stores scan results in PostgreSQL, supports Google OAuth-based user accounts with DB-backed sessions, offers public and authenticated analysis/reporting features, and exposes several helper/report/export endpoints around stored analyses. The main production entry point is `go-server/cmd/server/main.go`.

## Assets

- **User accounts and sessions** — Google-linked identities, session cookies, roles, and entitlement state. Compromise enables impersonation and access to user-scoped features.
- **Private analyses and user-provided selectors** — some analyses include custom selectors or user-provided intelligence and are explicitly intended to be visible only to the owner because they can reveal internal mail infrastructure and vendor relationships.
- **Stored historical analyses and metadata** — scan history, posture hashes, drift history, telemetry, and related report artifacts. Even when results are public by design, integrity and correct access scoping matter.
- **Notification endpoints and webhook secrets** — user-managed webhook URLs and optional shared secrets for watchlist notifications.
- **Application secrets and third-party API credentials** — session secret, OAuth credentials, database URL, SecurityTrails and other provider keys, Discord webhook configuration.
- **Admin capabilities** — `/ops` and related administration functions can run operational workflows and manipulate user/session data.

## Trust Boundaries

- **Browser to server** — all route inputs, query parameters, headers, uploads, and form fields are attacker-controlled.
- **Public to authenticated** — some report and helper surfaces are public, while user history, watchlist management, zone retention, and private analysis access require authentication.
- **Authenticated user to admin** — admin dashboard and operational task execution must be isolated from normal users.
- **Server to PostgreSQL** — stored analyses, sessions, users, and webhook configuration cross this boundary; authorization mistakes here can disclose or corrupt sensitive data.
- **Server to external services** — Google OAuth, SecurityTrails, Wayback, BIMI logo hosts, Discord/webhook destinations, and DNS-related tools all cross external network boundaries and must resist SSRF and secret leakage.
- **Production vs dev-only behavior** — mockup/dev sandbox behavior is out of scope; only production-reachable paths should influence findings.

## Scan Anchors

- Production entry point: `go-server/cmd/server/main.go`
- High-risk code areas: `go-server/internal/handlers/analysis_*`, `compare.go`, `agentpkg/`, `adminpkg/`, `watchlist.go`, `proxy.go`, `zone.go`, `go-server/internal/middleware/`
- Public surfaces: report views, analysis APIs, badge/agent/helper routes, snapshot/compare/remediation paths, BIMI proxy
- Authenticated/admin surfaces: `/auth/*`, watchlist, zone retention/import features, `/ops`, `/admin`
- Dev-only areas to usually ignore: tests, mockup/dev preview behavior, non-production-only scaffolding unless a production route reaches it

## Threat Categories

### Spoofing

The application relies on Google OAuth 2.0 plus DB-backed session cookies. The system must generate unpredictable OAuth state, nonce, PKCE verifier values, and session identifiers, validate OAuth callback claims, and treat every request without a valid server-loaded session as unauthenticated. Webhook-style or callback-style integrations must not trust caller identity without server-side verification.

### Tampering

Attackers can submit domains, selector values, query parameters, uploaded zone files, and webhook URLs. The application must validate and constrain all such inputs before persisting them, using them in business logic, or turning them into outbound network requests. Stored analysis comparisons, exports, and helper features must not let attackers tamper with or substitute other users’ records.

### Information Disclosure

This project intentionally serves many reports publicly, but private analyses are a distinct sensitive asset and must remain owner-only across every route that can load an analysis by ID or domain. Logs, exports, helper pages, and derived artifacts must not leak webhook secrets, OAuth material, API keys, internal IPs, or private analysis metadata. Any helper endpoint that wraps a stored analysis inherits the same privacy requirements as the main report/API routes.

### Denial of Service

The app performs network-heavy analysis and supports uploads and outbound fetches. Public routes must bound request size, external-call timing, redirect depth, and repeated analysis triggering so attackers cannot exhaust compute, network budget, or database capacity. Auth and report helpers should avoid attacker-controlled amplification.

### Elevation of Privilege

Server-side authorization is critical because the app mixes public, authenticated, premium, and admin features. All routes that access stored analyses, user watchlist data, zone imports, and admin operations must enforce ownership or role checks consistently. Admin task execution must only run a strict allowlist and must never expose a path for lower-privilege users to trigger command execution or sensitive maintenance actions.