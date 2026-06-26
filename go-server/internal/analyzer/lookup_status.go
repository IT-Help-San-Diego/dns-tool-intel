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

// Per-protocol record-presence state keys. Each status-aware simple-record
// analyzer (BIMI/MTA-STS/TLS-RPT/CAA) publishes its tri-state outcome under one
// of these keys so the posture layer can tell a transient/indeterminate lookup
// apart from a confirmed absence — mirroring spf_state/dmarc_state/dnssec_state.
const (
        mapKeyBimiState   = "bimi_state"
        mapKeyMtaStsState = "mta_sts_state"
        mapKeyTlsrptState = "tlsrpt_state"
        mapKeyCaaState    = "caa_state"
)

// isIndeterminateLookup reports whether a lookup status is non-authoritative — a
// transient resolver failure (LookupError) or a multi-resolver conflict with no
// majority winner (LookupConflict, DNS mid-propagation). Such an outcome must
// NEVER be read as a confirmed record absence (RFC 7208 §4.6, RFC 7489 §6.6.3);
// the caller emits statusIndeterminate / triStateIndeterminate instead of a
// false "no record found".
func isIndeterminateLookup(status dnsclient.LookupStatus) bool {
        return status == dnsclient.LookupError || status == dnsclient.LookupConflict
}

// indeterminateLookupMessage builds the honest user-facing message for a record
// whose DNS lookup did not complete authoritatively, distinguishing a transient
// failure from a resolver conflict. It states plainly that this is NOT evidence
// of absence so a re-run is invited rather than a false "not configured"
// conclusion being drawn.
func indeterminateLookupMessage(protocol string, status dnsclient.LookupStatus) string {
        if status == dnsclient.LookupConflict {
                return protocol + " could not be confirmed: public resolvers returned conflicting answers with no majority winner (DNS may be mid-propagation). This is not evidence that " + protocol + " is absent — re-run once the change has settled."
        }
        return protocol + " could not be verified: the DNS lookup did not complete (transient SERVFAIL/timeout/network error). This is not evidence that " + protocol + " is absent — re-run before concluding it is unconfigured."
}
