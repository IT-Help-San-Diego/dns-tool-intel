# Contributing to DNS Tool

## SonarCloud Quality Gate Standards

All contributions must meet the following quality standards enforced by SonarCloud.

### Test Coverage

- All new code must have **80%+ test coverage**.
- Run tests with coverage before pushing:
  ```bash
  go test ./go-server/... -cover -count=1
  ```
- Use table-driven tests with descriptive names.
- Cover edge cases: empty strings, nil inputs, boundary values, malformed data.

### Code Smells

- No new code smells rated **CRITICAL** or above.
- No new duplicated string literals — extract to constants.
- Keep functions focused and under reasonable complexity thresholds.

### Security Hotspots

- All security hotspots must be reviewed before merge.
- Never hard-code secrets, API keys, or credentials.
- Use environment variables for sensitive configuration.

### Duplication

- No new duplicated blocks or string literals.
- Extract repeated strings into package-level constants.
- Reuse existing utility functions rather than duplicating logic.

## Pre-Push Checklist

1. **Go tests pass with coverage:**
   ```bash
   go test ./go-server/... -cover -count=1
   ```

2. **Minify JS after changes:**
   ```bash
   npx terser static/js/main.js -o static/js/main.min.js --compress --mangle
   ```

3. **Minify CSS after changes:**
   ```bash
   npx csso static/css/custom.css -o static/css/custom.min.css
   ```

4. **Run quality gate scripts:**
   ```bash
   node scripts/audit-css-cohesion.js
   node scripts/feature-inventory.js
   node scripts/validate-scientific-colors.js
   ```

5. **Build the binary:**
   ```bash
   bash build.sh
   ```

## Version Bump Protocol

1. Bump `Version` in `go-server/internal/config/config.go`.
2. Run `bash build.sh` to compile the new version into the binary.
3. Restart the application workflow.

The version is compiled at build time via `-ldflags` in `build.sh`. The `Version` variable in `config.go` is the single source of truth.

## Code Style

- Follow existing patterns and conventions in the codebase.
- Use Go standard formatting (`gofmt`).
- No inline `onclick`, `onchange`, or `style=""` in templates — use `addEventListener` in nonce'd script blocks.
- Every CSS/template change must be verified at 375px width.
- All domain/IP input fields must include `autocapitalize="none" spellcheck="false" autocomplete="off"`.

## SonarCloud Coverage Targets by Package

| Package | Minimum Target |
|---------|---------------|
| New packages | 80%+ |
| `analyzer` | 80%+ |
| `dnsclient` | 80%+ |
| `middleware` | 65%+ |
| `notifier` | 80%+ |
| `scanner` | 80%+ |
| `icae` | 80%+ |
| `handlers` | Improve from baseline |
| `cmd/probe` | 45%+ |
