// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny science
package analyzer

import "strings"

const (
        mapKeyDaneAnalysis  = "dane_analysis"
        mapKeyDmarcAnalysis = "dmarc_analysis"
)

type PostureDiffField struct {
        Label    string
        Previous string
        Current  string
        Severity string
}

func ComputePostureDiff(prev, curr map[string]any) []PostureDiffField {
        type fieldSpec struct {
                label   string
                section string
                key     string
        }

        fields := []fieldSpec{
                {"SPF Status", "spf_analysis", mapKeyStatus},
                {"DMARC Status", mapKeyDmarcAnalysis, mapKeyStatus},
                {"DMARC Policy", mapKeyDmarcAnalysis, "policy"},
                {"DKIM Status", "dkim_analysis", mapKeyStatus},
                {"MTA-STS Status", "mta_sts_analysis", mapKeyStatus},
                {"MTA-STS Mode", "mta_sts_analysis", "mode"},
                {"TLS-RPT Status", "tlsrpt_analysis", mapKeyStatus},
                {"BIMI Status", "bimi_analysis", mapKeyStatus},
                {"DANE Status", mapKeyDaneAnalysis, mapKeyStatus},
                {"CAA Status", "caa_analysis", mapKeyStatus},
                {"DNSSEC Status", "dnssec_analysis", mapKeyStatus},
                {"Mail Posture", "mail_posture", "label"},
        }

        var diffs []PostureDiffField

        // Tri-state drift suppression: when DANE or DNSSEC presence is
        // indeterminate on EITHER side (a transient lookup failure, not an
        // authoritative answer), do not emit a presence/status diff for it. A
        // probe we could not complete is not evidence that posture changed —
        // counting it produced the false-flapping (e.g. nlnetlabs.nl toggling
        // 44× on transient DANE failures). The verdict text already says
        // "could not verify"; drift must stay silent rather than fabricate a
        // removal/restoration pair.
        daneIndet := postureFieldEquals(prev, mapKeyDaneAnalysis, "dane_state", dnssecStateIndeterminate) ||
                postureFieldEquals(curr, mapKeyDaneAnalysis, "dane_state", dnssecStateIndeterminate)
        dnssecIndet := postureFieldEquals(prev, "dnssec_analysis", mapKeyDnssecState, dnssecStateIndeterminate) ||
                postureFieldEquals(curr, "dnssec_analysis", mapKeyDnssecState, dnssecStateIndeterminate) ||
                postureFieldEquals(prev, "dnssec_analysis", mapKeyDnssecState, dnssecStateUnmeasured) ||
                postureFieldEquals(curr, "dnssec_analysis", mapKeyDnssecState, dnssecStateUnmeasured)
        spfIndet := postureFieldEquals(prev, "spf_analysis", mapKeySpfState, spfStateIndeterminate) ||
                postureFieldEquals(curr, "spf_analysis", mapKeySpfState, spfStateIndeterminate)
        dmarcIndet := postureFieldEquals(prev, mapKeyDmarcAnalysis, mapKeyDmarcState, dmarcStateIndeterminate) ||
                postureFieldEquals(curr, mapKeyDmarcAnalysis, mapKeyDmarcState, dmarcStateIndeterminate)
        // Extend the same tri-state drift suppression to the auxiliary protocols. A
        // transient CAA/MTA-STS/TLS-RPT/BIMI lookup failure (state=indeterminate on
        // either side) is not evidence that posture changed — suppress its status/mode
        // and record/tag diffs rather than fabricate a removal/restoration pair.
        caaIndet := postureFieldEquals(prev, "caa_analysis", mapKeyCaaState, triStateIndeterminate) ||
                postureFieldEquals(curr, "caa_analysis", mapKeyCaaState, triStateIndeterminate)
        mtaStsIndet := postureFieldEquals(prev, "mta_sts_analysis", mapKeyMtaStsState, triStateIndeterminate) ||
                postureFieldEquals(curr, "mta_sts_analysis", mapKeyMtaStsState, triStateIndeterminate)
        tlsRptIndet := postureFieldEquals(prev, "tlsrpt_analysis", mapKeyTlsrptState, triStateIndeterminate) ||
                postureFieldEquals(curr, "tlsrpt_analysis", mapKeyTlsrptState, triStateIndeterminate)
        bimiIndet := postureFieldEquals(prev, "bimi_analysis", mapKeyBimiState, triStateIndeterminate) ||
                postureFieldEquals(curr, "bimi_analysis", mapKeyBimiState, triStateIndeterminate)
        // DKIM joins the same tri-state contract via its selector-census state:
        // indeterminate means at least one selector probe never completed, so
        // neither the status verdict nor the selector set can be compared —
        // one side's census may simply be missing the selectors the other side
        // saw. An absent_confirmed census (every probe authoritatively
        // answered, nothing found) is NOT suppressed: that is real drift.
        dkimIndet := postureFieldEquals(prev, mapKeyDkimAnalysis, mapKeyDkimState, triStateIndeterminate) ||
                postureFieldEquals(curr, mapKeyDkimAnalysis, mapKeyDkimState, triStateIndeterminate)

        // The DKIM status is a verdict DERIVED from the published key records
        // plus provider inference — not a measurement. When both scans'
        // canonicalized record sets are identical the domain's DKIM did not
        // change, so a status flip is representation/parser/inference skew and
        // reporting it fabricates drift ("it is the same key" — 2026-08-03
        // walkthrough, defect 2). Suppression requires BOTH sets non-empty: an
        // empty set proves nothing, so a disappearance still surfaces, and any
        // real record change makes the sets differ. The genuine mover (MX, SPF)
        // reports through its own fields.
        pset := canonicalDKIMRecordSet(prev)
        dkimSameRecords := pset != "" && pset == canonicalDKIMRecordSet(curr)

        // Which status rows to suppress — same map idiom as suppressSorted below.
        suppressStatus := map[string]bool{
                "DKIM Status":    dkimSameRecords || dkimIndet,
                "DANE Status":    daneIndet,
                "DNSSEC Status":  dnssecIndet,
                "SPF Status":     spfIndet,
                "DMARC Status":   dmarcIndet,
                "DMARC Policy":   dmarcIndet,
                "CAA Status":     caaIndet,
                "MTA-STS Status": mtaStsIndet,
                "MTA-STS Mode":   mtaStsIndet,
                "TLS-RPT Status": tlsRptIndet,
                "BIMI Status":    bimiIndet,
                "Mail Posture":   spfIndet || dmarcIndet || dkimIndet,
        }

        for _, f := range fields {
                if suppressStatus[f.label] {
                        continue
                }
                prevVal := extractPostureField(prev, f.section, f.key)
                currVal := extractPostureField(curr, f.section, f.key)
                if prevVal != currVal {
                        diffs = append(diffs, PostureDiffField{
                                Label:    f.label,
                                Previous: displayVal(prevVal),
                                Current:  displayVal(currVal),
                                Severity: classifyDriftSeverity(f.label, prevVal, currVal),
                        })
                }
        }

        type sortedSpec struct {
                label string
                fn    func(map[string]any) string
        }
        sortedFields := []sortedSpec{
                {"DKIM Selectors", extractSortedSelectors},
                {"CAA Tags", extractSortedCAATags},
                {"SPF Records", func(r map[string]any) string { return extractSortedRecords(r, "spf_analysis", "records") }},
                {"DMARC Records", func(r map[string]any) string { return extractSortedRecords(r, mapKeyDmarcAnalysis, "records") }},
                {"MX Records", extractSortedMX},
                {"NS Records", extractSortedNS},
        }
        // Record/tag set diffs are presence claims too: an indeterminate SPF/DMARC/CAA
        // lookup yields an empty array that is NOT a confirmed removal. Suppress those
        // set diffs on the same tri-state basis as the status diffs above.
        suppressSorted := map[string]bool{
                "SPF Records":    spfIndet,
                "DMARC Records":  dmarcIndet,
                "CAA Tags":       caaIndet,
                "DKIM Selectors": dkimIndet,
        }
        for _, sf := range sortedFields {
                if suppressSorted[sf.label] {
                        continue
                }
                prevVal := sf.fn(prev)
                currVal := sf.fn(curr)
                if prevVal != currVal {
                        diffs = append(diffs, PostureDiffField{
                                Label:    sf.label,
                                Previous: displayVal(prevVal),
                                Current:  displayVal(currVal),
                                Severity: classifyDriftSeverity(sf.label, prevVal, currVal),
                        })
                }
        }

        if !daneIndet {
                prevDANE := extractPostureBool(prev, mapKeyDaneAnalysis, "has_dane")
                currDANE := extractPostureBool(curr, mapKeyDaneAnalysis, "has_dane")
                if prevDANE != currDANE {
                        diffs = append(diffs, PostureDiffField{
                                Label:    "DANE Present",
                                Previous: displayVal(prevDANE),
                                Current:  displayVal(currDANE),
                                Severity: classifyDriftSeverity("DANE Present", prevDANE, currDANE),
                        })
                }
        }

        return diffs
}

// postureFieldEquals reports whether a section's field equals want
// (case-insensitively). Used to detect indeterminate tri-state so drift
// computation can skip presence/status fields that could not be confirmed.
func postureFieldEquals(results map[string]any, section, key, want string) bool {
        return extractPostureField(results, section, key) == strings.ToLower(want)
}

func displayVal(v string) string {
        v = strings.TrimSpace(v)
        if v == "" {
                return "(none)"
        }
        return v
}
