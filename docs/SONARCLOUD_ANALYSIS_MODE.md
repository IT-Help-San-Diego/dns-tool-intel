# SonarCloud Analysis Mode Configuration

## Current Setup

This project uses **CI-based analysis** via the GitHub Actions workflow
(`.github/workflows/sonarcloud.yml`). The workflow:

1. Checks out the code with full history (`fetch-depth: 0`)
2. Runs Go tests with coverage (`coverage.out`)
3. Normalizes coverage paths for SonarCloud
4. Runs the SonarCloud scanner, which reads `sonar-project.properties`

The `sonar-project.properties` file defines:
- `sonar.sources=go-server` — only Go server code is analyzed
- `sonar.exclusions` — excludes test fixtures, generated code, vendor, docs
- `sonar.issue.ignore.multicriteria.*` — legitimate suppressions with SECINTENT documentation

## Required: Disable Automatic Analysis

SonarCloud offers two analysis modes. **Only one should be active at a time.**
When Automatic Analysis is ON, it ignores `sonar-project.properties` and scans
the entire repository — including `dns-eval/` fixture JSONs (which contain
strings like "password" from security scan outputs), `security/` semgrep rules,
and other non-source directories. This inflates the issue count with hundreds
of false positives.

### Steps to Disable Automatic Analysis

1. Go to [SonarCloud](https://sonarcloud.io)
2. Navigate to **IT-Help-San-Diego / dns-tool-intel**
3. Click **Administration** (gear icon, bottom-left)
4. Select **Analysis Method**
5. Under "Automatic Analysis", toggle the switch **OFF**
6. Confirm the CI-based analysis workflow is listed as active

After disabling Automatic Analysis:
- Push any commit to `main` to trigger the CI workflow
- The SonarCloud dashboard will update with accurate results
- Issue counts should drop significantly as false positives are eliminated

### Verification

After the next CI run completes:
- Check that `dns-eval/` files no longer appear in the SonarCloud issue list
- Check that `security/` semgrep rules are no longer flagged
- Confirm the issue count reflects only `go-server/` source code
- Verify coverage data appears correctly on the SonarCloud dashboard

## Security Hotspot Reviews

Security Hotspots require manual triage in the SonarCloud UI. They cannot be
resolved through code changes. After disabling Automatic Analysis, review the
remaining Security Hotspots:

1. Go to the project's **Security Hotspots** tab
2. Review each hotspot and mark as "Safe", "Fixed", or "Acknowledged"
3. The Quality Gate requires 100% of Security Hotspots to be reviewed
