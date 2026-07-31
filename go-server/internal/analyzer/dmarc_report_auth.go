// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny science
package analyzer

import (
        "context"
        "fmt"
        "log/slog"
        "strings"

        "golang.org/x/net/publicsuffix"

        "dnstool/go-server/internal/dnsclient"
)

// Tri-state authorization outcome per RFC 7489 §7.1. "indeterminate" exists so a
// failed DNS probe is never reported as "unauthorized" (a false negative).
const (
        reportAuthAuthorized    = "authorized"
        reportAuthUnauthorized  = "unauthorized"
        reportAuthIndeterminate = "indeterminate"
        // reportAuthMaxAttempts retries ONLY indeterminate (failed) lookups. The deep
        // "<domain>._report._dmarc.<external>" name lives on the reporting provider's
        // infrastructure and is rarely cached, so a single timeout used to flip the
        // verdict scan-to-scan. A definitive answer (resolved/absent) stops early.
        reportAuthMaxAttempts = 3
)

func (a *Analyzer) ValidateDMARCExternalAuth(ctx context.Context, domain string, dmarcData map[string]any) map[string]any {
        result := map[string]any{
                "status":           "success",
                "checked":          false,
                "external_domains": []map[string]any{},
                "issues":           []string{},
        }

        ruaStr := getStr(dmarcData, "rua")
        rufStr := getStr(dmarcData, "ruf")

        // RFC 7489 §7.1: the external-authorization record is named after the
        // domain that PUBLISHES the DMARC record. When coverage is inherited via
        // §6.6.3 organizational-domain fallback, the rua/ruf addresses come from
        // the org record, so external receivers authorize the org domain — not
        // the scanned subdomain. Checking <subdomain>._report._dmarc.<external>
        // here would fabricate a false "unauthorized" finding.
        reportingDomain := domain
        if fallback, _ := dmarcData["org_domain_fallback"].(bool); fallback {
                if od := getStr(dmarcData, "org_domain"); od != "" {
                        reportingDomain = od
                }
        }

        externalDomains := collectExternalDomains(reportingDomain, ruaStr, rufStr)
        if len(externalDomains) == 0 {
                result[mapKeyMessage] = "No external reporting domains detected"
                return result
        }

        result["checked"] = true
        var domainResults []map[string]any
        issues := []string{}
        notices := []string{}
        var unauthorized, indeterminate int

        for extDomain, sources := range externalDomains {
                dr := a.checkExternalAuth(ctx, reportingDomain, extDomain, sources)
                domainResults = append(domainResults, dr)
                switch dr["auth_state"] {
                case reportAuthUnauthorized:
                        unauthorized++
                        issues = append(issues, fmt.Sprintf("External domain %s has not authorized %s to send DMARC reports (missing %s._report._dmarc.%s TXT record)", extDomain, reportingDomain, reportingDomain, extDomain))
                case reportAuthIndeterminate:
                        indeterminate++
                        notices = append(notices, fmt.Sprintf("Could not verify external reporting authorization for %s — the DNS lookup for %s._report._dmarc.%s did not complete. Treated as unverified, not a finding; re-run to confirm.", extDomain, reportingDomain, extDomain))
                }
        }

        total := len(externalDomains)
        switch {
        case unauthorized > 0:
                // An authoritative answer says the authorization record is not published.
                result["status"] = "warning"
                result[mapKeyMessage] = fmt.Sprintf("%d of %d external reporting domains missing authorization", unauthorized, total)
        case indeterminate > 0:
                // No definitive answer — surface honestly instead of a false "missing".
                result["status"] = reportAuthIndeterminate
                result[mapKeyMessage] = fmt.Sprintf("Could not verify %d of %d external reporting domains — DNS lookup did not complete", indeterminate, total)
        default:
                result[mapKeyMessage] = fmt.Sprintf("All %d external reporting domains properly authorized", total)
        }

        result["external_domains"] = domainResults
        result["issues"] = issues
        result["notices"] = notices
        return result
}

func collectExternalDomains(domain, ruaStr, rufStr string) map[string][]string {
        external := make(map[string][]string)
        domainOrg, domainOrgIndeterminate := orgDomain(domain)

        for _, d := range ExtractMailtoDomains(ruaStr) {
                if !sameOrgDomain(d, domain, domainOrg, domainOrgIndeterminate) {
                        external[d] = appendUnique(external[d], "rua")
                }
        }
        for _, d := range ExtractMailtoDomains(rufStr) {
                if !sameOrgDomain(d, domain, domainOrg, domainOrgIndeterminate) {
                        external[d] = appendUnique(external[d], "ruf")
                }
        }
        return external
}

// orgDomain returns the registrable organizational domain for d per the
// Public Suffix List.
//
// Tri-state (Zero-Fabrication): when EffectiveTLDPlusOne errors (unlisted/
// unknown suffix in the compiled-in PSL snapshot), indeterminate is true and
// the returned string is NOT a derived organizational domain — it is the
// caller's input, lowercased, as a safe fallback key. The caller must not
// treat that as a real organizational-domain derivation; doing so would
// silently collapse distinct domains into one org bucket (a fabricated
// grouping) and report a subdomain as an apex. Absence in the local snapshot
// is not absence in the world.
func orgDomain(d string) (org string, indeterminate bool) {
	d = strings.TrimRight(d, ".")
	reg, err := publicsuffix.EffectiveTLDPlusOne(d)
	if err != nil {
		return strings.ToLower(d), true
	}
	return strings.ToLower(reg), false
}

// sameOrgDomain reports whether a and b share an organizational domain.
// bOrg is orgDomain(b) when that derivation is determinate; it is ignored
// when indeterminate (the org-domain relationship could not be established).
// Conservative on uncertainty: an indeterminate lookup is never treated as
// proof of a shared org domain, and EqualFold(a,b) already covered the
// exact-match case — so uncertain input cannot fabricate a "same org" claim.
func sameOrgDomain(a, b, bOrg string, bOrgIndeterminate bool) bool {
	if strings.EqualFold(a, b) {
		return true
	}
	if bOrgIndeterminate {
		return false
	}
	aOrg, aIndeterminate := orgDomain(a)
	if aIndeterminate {
		return false
	}
	return strings.EqualFold(aOrg, bOrg)
}

func appendUnique(slice []string, val string) []string {
        for _, s := range slice {
                if s == val {
                        return slice
                }
        }
        return append(slice, val)
}

func (a *Analyzer) checkExternalAuth(ctx context.Context, reportingDomain, externalDomain string, sources []string) map[string]any {
        authDomain := fmt.Sprintf("%s._report._dmarc.%s", reportingDomain, externalDomain)
        records, status := a.resolveReportAuth(ctx, authDomain)

        var authRecord string
        for _, rec := range records {
                if strings.HasPrefix(strings.ToLower(rec), "v=dmarc1") {
                        authRecord = rec
                        break
                }
        }

        // Three-state classification per RFC 7489 §7.1:
        //   - record present                        -> authorized
        //   - definitive answer, no DMARC record    -> unauthorized (NXDOMAIN/NODATA/
        //     resolved-but-not-DMARC: authorization is genuinely absent)
        //   - lookup never completed                -> indeterminate (NOT a finding)
        authState := reportAuthIndeterminate
        switch {
        case authRecord != "":
                authState = reportAuthAuthorized
        case status == dnsclient.LookupResolved || status == dnsclient.LookupAbsent:
                authState = reportAuthUnauthorized
        }

        slog.Debug("DMARC external auth check",
                "auth_domain", authDomain,
                "records_count", len(records),
                "lookup_status", int(status),
                "auth_state", authState,
        )

        return map[string]any{
                "external_domain": externalDomain,
                "sources":         sources,
                "auth_domain":     authDomain,
                "authorized":      authState == reportAuthAuthorized,
                "auth_state":      authState,
                "auth_record":     authRecord,
                "confidence":      ConfidenceObservedMap(MethodDNSRecord),
        }
}

// resolveReportAuth resolves the authorization TXT name and returns the records
// plus a definitive/indeterminate status. It prefers a status-aware DNS client
// (so a failed probe is reported as LookupError, never as absence) and retries
// ONLY indeterminate results. DNS clients without status support fall back to the
// plain query, which can only tell "resolved" from "empty".
func (a *Analyzer) resolveReportAuth(ctx context.Context, authDomain string) ([]string, dnsclient.LookupStatus) {
        sq, ok := a.DNS.(interface {
                QueryDNSWithStatus(context.Context, string, string) ([]string, dnsclient.LookupStatus)
        })
        if !ok {
                records := a.DNS.QueryDNS(ctx, "TXT", authDomain)
                if len(records) > 0 {
                        return records, dnsclient.LookupResolved
                }
                return nil, dnsclient.LookupAbsent
        }

        var records []string
        status := dnsclient.LookupError
        for attempt := 0; attempt < reportAuthMaxAttempts; attempt++ {
                records, status = sq.QueryDNSWithStatus(ctx, "TXT", authDomain)
                if status != dnsclient.LookupError || ctx.Err() != nil {
                        break // definitive answer, or context done — stop retrying
                }
        }
        return records, status
}
