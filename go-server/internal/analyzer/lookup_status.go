// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny science
package analyzer

import (
        "context"

        "dnstool/go-server/internal/dnsclient"
)

// statusIndeterminate is the top-level analyzer status for a check whose primary
// DNS lookup did not complete (transient SERVFAIL/timeout/network error). It is
// deliberately distinct from "missing": absence may only be asserted from an
// authoritative answer (RFC 7208 §4.6 for SPF, RFC 7489 §6.6.3 for DMARC). The
// same convention already governs DMARC external-reporting authorization
// (reportAuthIndeterminate) and the DANE/DNSSEC presence tri-states.
const statusIndeterminate = "indeterminate"

// Tri-state record-presence vocabulary shared across status-aware analyzers,
// mirroring the DANE (daneState*) and DNSSEC (dnssecState*) constants.
const (
        triStatePresent       = "present"
        triStateAbsentConf    = "absent_confirmed"
        triStateIndeterminate = "indeterminate"
)

// lookupStatusMaxAttempts caps how many times resolveWithStatus retries a purely
// indeterminate (LookupError) outcome before giving up. A definitive answer
// (resolved or authoritative absence) stops retrying immediately. Mirrors
// reportAuthMaxAttempts.
const lookupStatusMaxAttempts = 3

// resolveWithStatus resolves recordType/domain and returns the records plus a
// definitive/indeterminate status. It prefers the status-aware DNS client
// (QueryDNSWithStatus) and retries ONLY indeterminate lookups, up to
// lookupStatusMaxAttempts; a resolved answer or an authoritative absence stops
// immediately. DNS clients without status support fall back to the flat QueryDNS
// (records => resolved, empty => absent) — they cannot distinguish transient
// failure from absence, but neither did the legacy path. This generalizes
// resolveReportAuth (RFC 7489 §7.1 reasoning) to any record type so SPF and DMARC
// never read a probe that timed out as a published-record absence.
func (a *Analyzer) resolveWithStatus(ctx context.Context, recordType, domain string) ([]string, dnsclient.LookupStatus) {
        sq, ok := a.DNS.(interface {
                QueryDNSWithStatus(context.Context, string, string) ([]string, dnsclient.LookupStatus)
        })
        if !ok {
                records := a.DNS.QueryDNS(ctx, recordType, domain)
                if len(records) > 0 {
                        return records, dnsclient.LookupResolved
                }
                return nil, dnsclient.LookupAbsent
        }

        var records []string
        status := dnsclient.LookupError
        for attempt := 0; attempt < lookupStatusMaxAttempts; attempt++ {
                records, status = sq.QueryDNSWithStatus(ctx, recordType, domain)
                if status != dnsclient.LookupError || ctx.Err() != nil {
                        break // definitive answer, or context done — stop retrying
                }
        }
        return records, status
}

// triStateFromStatus maps a dnsclient.LookupStatus onto the shared tri-state
// presence vocabulary (present / absent_confirmed / indeterminate).
func triStateFromStatus(status dnsclient.LookupStatus) string {
        switch status {
        case dnsclient.LookupResolved:
                return triStatePresent
        case dnsclient.LookupAbsent:
                return triStateAbsentConf
        default:
                return triStateIndeterminate
        }
}
