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
                postureFieldEquals(curr, "dnssec_analysis", mapKeyDnssecState, dnssecStateIndeterminate)
        spfIndet := postureFieldEquals(prev, "spf_analysis", mapKeySpfState, spfStateIndeterminate) ||
                postureFieldEquals(curr, "spf_analysis", mapKeySpfState, spfStateIndeterminate)
        dmarcIndet := postureFieldEquals(prev, mapKeyDmarcAnalysis, mapKeyDmarcState, dmarcStateIndeterminate) ||
                postureFieldEquals(curr, mapKeyDmarcAnalysis, mapKeyDmarcState, dmarcStateIndeterminate)

        for _, f := range fields {
                if daneIndet && f.label == "DANE Status" {
                        continue
                }
                if dnssecIndet && f.label == "DNSSEC Status" {
                        continue
                }
                if spfIndet && f.label == "SPF Status" {
                        continue
                }
                if dmarcIndet && (f.label == "DMARC Status" || f.label == "DMARC Policy") {
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
        for _, sf := range sortedFields {
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
