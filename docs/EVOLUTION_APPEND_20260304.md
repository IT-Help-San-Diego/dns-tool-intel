# Evolution Log — v26.34.02 → v26.34.03

**Date:** 2026-03-04  
**Session:** Bug Fixes, Deprecation Cleanup, Deployment Validation

---

## v26.34.03 — Template Data + Deprecation Fixes (2026-03-04)

### Bugs Fixed

1. **Missing `MaintenanceNote`/`BetaPages` in NoRoute 404 handler** (`main.go`): The custom 404 handler rendered `index.html` without passing `MaintenanceNote` or `BetaPages` template variables. Any active maintenance banner or beta page list would silently disappear on 404 pages. Fixed by injecting both variables from config.
2. **Missing `MaintenanceNote`/`BetaPages` in `indexFlashData`** (`analysis.go`): The `indexFlashData()` helper builds template data for all flash/error paths during analysis. It omitted both variables, causing maintenance banners to vanish on validation errors, duplicate submissions, and other flash-redirect paths. Fixed by adding both to the shared helper.
3. **Recovery middleware lacked template data passthrough** (`middleware.go`): The panic recovery middleware rendered `index.html` with only `Flash*` and `AppVersion` — no `MaintenanceNote` or `BetaPages`. Changed signature to `Recovery(appVersion string, opts ...map[string]any)` to accept optional extra template data. Backward compatible.
4. **Deprecated `strings.Title` usage** (`helpers.go`, `funcs.go`): Two call sites used `strings.Title()`, deprecated since Go 1.18 and flagged by `go vet`. Replaced with `cases.Title(language.English).String()` from `golang.org/x/text`. Both `helpers.go` and `funcs.go` updated.

### Pattern Identified

- **Every handler rendering `index.html` MUST pass `MaintenanceNote` and `BetaPages`** — these are site-wide template variables. Missing them causes silent UI regression (no error, just missing content). Future handlers must follow this contract.

### Build & Deploy

- `go vet ./go-server/...` clean
- Config, middleware, cmd tests passing
- Binary rebuilt, dev server confirmed v26.34.03 with 200 on all endpoints
- Deployed to production: `dnstool.it-help.tech` serving v26.34.03, healthz 200
- Git pushed to `origin/replit-agent`: `b617e494..19f3b39d`
- Intel repo synced

---

## Process Observations

- **Deployment startup 500s**: Replit's deployment healthcheck hits `/` before the Go server finishes initialization (~6 seconds). During this window, healthchecks return 500. The server recovers once initialization completes. This is cosmetic (no user impact) but noisy in deployment logs.
- **Template data contract enforcement**: No compile-time or test-time check ensures `MaintenanceNote`/`BetaPages` are passed to every `index.html` render. A template data builder or integration test scanning all render calls would prevent recurrence.
