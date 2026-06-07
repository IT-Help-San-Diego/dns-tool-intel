// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
package icsae

import "testing"

// refs is a tiny constructor for verified weakness refs in tests.
func refs(conf string, cwe, capec, vrt []string) *WeaknessRefs {
        return &WeaknessRefs{CWE: cwe, CAPEC: capec, VRT: vrt, MappingConfidence: conf, MappingRationale: "test"}
}

func itemByControl(q RemediationQueue, id string) (RemediationItem, bool) {
        for _, it := range q.Items {
                if it.ControlID == id {
                        return it, true
                }
        }
        return RemediationItem{}, false
}

// TestRemediationQueueOrdersByTriageRank proves the refs DRIVE the order:
// a no-position spoofing fix outranks an on-path DNSSEC fix of equal severity,
// which outranks an unmapped control.
func TestRemediationQueueOrdersByTriageRank(t *testing.T) {
        res := Result{Results: []ControlResult{
                {ID: "DMARC_ENFORCEMENT", Title: "DMARC", Status: "failed", Severity: "high",
                        FailExplanation: "p=none", RFCs: []string{"RFC7489"},
                        WeaknessRefs: refs("high", []string{"CWE-290"}, []string{"CAPEC-151"}, []string{"VRT:email_spoofing_to_inbox_due_to_missing_or_misconfigured_dmarc_on_email_domain"})},
                {ID: "DNSSEC_AUTHENTICATED", Title: "DNSSEC", Status: "failed", Severity: "high",
                        FailExplanation: "unsigned", RFCs: []string{"RFC4033"},
                        WeaknessRefs: refs("high", []string{"CWE-345"}, []string{"CAPEC-142"}, []string{"VRT:missing_dnssec"})},
                {ID: "CAA_RESTRICTION_PRESENT", Title: "CAA", Status: "failed", Severity: "high",
                        FailExplanation: "no CAA"},
        }}
        fc := FixClassification{
                RealFixCount: 3,
                RealFixes:    []string{"DMARC_ENFORCEMENT", "DNSSEC_AUTHENTICATED", "CAA_RESTRICTION_PRESENT"},
        }

        q := BuildRemediationQueue(res, fc, false)
        if len(q.Items) != 3 {
                t.Fatalf("expected 3 items, got %d", len(q.Items))
        }
        if q.Items[0].ControlID != "DMARC_ENFORCEMENT" {
                t.Errorf("rank 1 should be DMARC (exploitable_now), got %s", q.Items[0].ControlID)
        }
        if q.Items[1].ControlID != dnssecGroupID {
                t.Errorf("rank 2 should be DNSSEC (conditional), got %s", q.Items[1].ControlID)
        }
        if q.Items[2].ControlID != "CAA_RESTRICTION_PRESENT" {
                t.Errorf("rank 3 should be unmapped CAA, got %s", q.Items[2].ControlID)
        }
        for i, it := range q.Items {
                if it.Rank != i+1 {
                        t.Errorf("item %d has rank %d, expected %d", i, it.Rank, i+1)
                }
        }
        // priority scores must be strictly descending given the inputs.
        if !(q.Items[0].PriorityScore > q.Items[1].PriorityScore && q.Items[1].PriorityScore > q.Items[2].PriorityScore) {
                t.Errorf("priority scores not strictly descending: %d %d %d",
                        q.Items[0].PriorityScore, q.Items[1].PriorityScore, q.Items[2].PriorityScore)
        }
}

func TestExploitClassDerivation(t *testing.T) {
        cases := []struct {
                name string
                refs *WeaknessRefs
                want string
        }{
                {"spoofing", refs("high", []string{"CWE-290"}, nil, nil), ExploitNow},
                {"capec_spoof_only", refs("high", nil, []string{"CAPEC-194"}, nil), ExploitNow},
                {"takeover", refs("high", nil, nil, []string{"VRT:subdomain_takeover"}), ExploitNow},
                {"onpath", refs("high", []string{"CWE-345"}, []string{"CAPEC-142"}, nil), ExploitConditional},
                {"missing_dnssec_vrt", refs("high", nil, nil, []string{"VRT:missing_dnssec"}), ExploitConditional},
                {"nil", nil, ExploitUnproven},
                {"mapped_no_offensive", refs("medium", []string{"CWE-200"}, nil, nil), ExploitUnproven},
        }
        for _, c := range cases {
                got, basis := exploitClass(c.refs)
                if got != c.want {
                        t.Errorf("%s: exploitClass = %q, want %q", c.name, got, c.want)
                }
                if basis == "" {
                        t.Errorf("%s: exploit basis is empty", c.name)
                }
        }
}

func TestBlastRadiusDerivation(t *testing.T) {
        cases := []struct {
                name string
                refs *WeaknessRefs
                want string
        }{
                {"spoofing", refs("high", []string{"CWE-290"}, nil, nil), BlastExternal},
                {"takeover", refs("high", nil, nil, []string{"VRT:subdomain_takeover"}), BlastExternal},
                {"onpath", refs("high", []string{"CWE-345"}, nil, nil), BlastResolution},
                {"nil", nil, BlastSelf},
        }
        for _, c := range cases {
                got, basis := blastRadius(c.refs)
                if got != c.want {
                        t.Errorf("%s: blastRadius = %q, want %q", c.name, got, c.want)
                }
                if basis == "" {
                        t.Errorf("%s: blast basis is empty", c.name)
                }
        }
}

func TestICD203Confidence(t *testing.T) {
        if lvl, _ := icd203Confidence(refs("high", []string{"CWE-290"}, nil, nil), false); lvl != ConfidenceHigh {
                t.Errorf("high mapping, fresh → expected high, got %q", lvl)
        }
        if lvl, _ := icd203Confidence(refs("medium", []string{"CWE-290"}, nil, nil), false); lvl != ConfidenceModerate {
                t.Errorf("medium mapping → expected moderate, got %q", lvl)
        }
        if lvl, _ := icd203Confidence(nil, false); lvl != ConfidenceModerate {
                t.Errorf("nil mapping → expected moderate, got %q", lvl)
        }
        if lvl, _ := icd203Confidence(refs("high", []string{"CWE-290"}, nil, nil), true); lvl != ConfidenceModerate {
                t.Errorf("high mapping but stale → expected demote to moderate, got %q", lvl)
        }
        if lvl, _ := icd203Confidence(nil, true); lvl != ConfidenceLow {
                t.Errorf("nil mapping + stale → expected low, got %q", lvl)
        }
        // basis must always be populated (ICD 203 requires an explicit basis).
        if _, basis := icd203Confidence(nil, false); basis == "" {
                t.Error("confidence basis must never be empty")
        }
}

// TestDNSSECGroupCollapsesToOneItem proves the queue stays consistent with the
// classifier's counted-once headline and uses a refs-carrying representative.
func TestDNSSECGroupCollapsesToOneItem(t *testing.T) {
        res := Result{Results: []ControlResult{
                {ID: "DNSSEC_CHAIN_TRUSTED", Title: "Chain", Status: "failed", Severity: "high",
                        FailExplanation: "chain"},
                {ID: "DNSSEC_AUTHENTICATED", Title: "Auth", Status: "failed", Severity: "high",
                        FailExplanation: "unsigned", RFCs: []string{"RFC4033"},
                        WeaknessRefs: refs("high", []string{"CWE-345"}, []string{"CAPEC-142"}, []string{"VRT:missing_dnssec"})},
                {ID: "DNSSEC_KEY_ROLLOVER", Title: "Rollover", Status: "failed", Severity: "medium",
                        FailExplanation: "manual"},
        }}
        fc := FixClassification{
                RealFixCount: 1,
                RealFixes:    []string{"DNSSEC_CHAIN_TRUSTED", "DNSSEC_AUTHENTICATED", "DNSSEC_KEY_ROLLOVER"},
        }
        q := BuildRemediationQueue(res, fc, false)
        if len(q.Items) != 1 {
                t.Fatalf("DNSSEC group should collapse to 1 item, got %d", len(q.Items))
        }
        it := q.Items[0]
        if it.ControlID != dnssecGroupID {
                t.Errorf("grouped item control id = %q, want %q", it.ControlID, dnssecGroupID)
        }
        if it.Title != "Deploy / Maintain DNSSEC" {
                t.Errorf("grouped item title = %q", it.Title)
        }
        if it.WeaknessRefs == nil {
                t.Error("representative should carry weakness refs (DNSSEC_AUTHENTICATED)")
        }
        if q.MappedCount != 1 {
                t.Errorf("MappedCount = %d, want 1", q.MappedCount)
        }
}

// TestQueueCountsAndCitations checks RealFixCount mirroring, MappedCount honesty,
// and that every item carries the attacker action (Zero-Fabrication: a Real Fix
// must be explainable).
func TestQueueCountsAndCitations(t *testing.T) {
        res := Result{Results: []ControlResult{
                {ID: "DMARC_ENFORCEMENT", Title: "DMARC", Status: "failed", Severity: "high",
                        FailExplanation: "p=none",
                        WeaknessRefs: refs("high", []string{"CWE-290"}, nil, nil)},
                {ID: "CAA_RESTRICTION_PRESENT", Title: "CAA", Status: "failed", Severity: "high",
                        FailExplanation: "no CAA"},
        }}
        fc := FixClassification{
                RealFixCount: 2,
                RealFixes:    []string{"DMARC_ENFORCEMENT", "CAA_RESTRICTION_PRESENT"},
        }
        q := BuildRemediationQueue(res, fc, false)
        if q.RealFixCount != 2 {
                t.Errorf("RealFixCount = %d, want 2", q.RealFixCount)
        }
        if q.MappedCount != 1 {
                t.Errorf("MappedCount = %d, want 1 (only DMARC is mapped)", q.MappedCount)
        }
        for _, it := range q.Items {
                if it.AttackerAction == "" {
                        t.Errorf("%s has no attacker action — a Real Fix must be explainable", it.ControlID)
                }
        }
}

// TestEmptyQueueWhenNoRealFixes guards the all-clear path.
func TestEmptyQueueWhenNoRealFixes(t *testing.T) {
        q := BuildRemediationQueue(Result{}, FixClassification{RealFixCount: 0}, false)
        if len(q.Items) != 0 || q.RealFixCount != 0 || q.MappedCount != 0 {
                t.Errorf("expected empty queue, got %+v", q)
        }
}

// TestPipelineQueueLengthMatchesRealFixCount locks the invariant that the queue
// length stays consistent with the classifier's counted-once headline through the
// real Evaluate -> ClassifyFromEval -> BuildRemediationQueue pipeline, so a future
// regression cannot silently drop or double-count a queued fix.
func TestPipelineQueueLengthMatchesRealFixCount(t *testing.T) {
        // An empty observations map drives controls to their failed/not-applicable
        // verdicts deterministically — enough to produce a non-trivial queue.
        fr := map[string]any{}
        ev := Evaluate(fr)
        fc := ClassifyFromEval(ev, fr)
        q := BuildRemediationQueue(ev, fc, false)

        if q.RealFixCount != fc.RealFixCount {
                t.Errorf("queue RealFixCount %d != classification RealFixCount %d", q.RealFixCount, fc.RealFixCount)
        }
        if len(q.Items) != q.RealFixCount {
                t.Errorf("queue has %d items but RealFixCount is %d", len(q.Items), q.RealFixCount)
        }
        // Ranks must be a contiguous 1..n sequence.
        for i, it := range q.Items {
                if it.Rank != i+1 {
                        t.Errorf("item %d rank = %d, want %d", i, it.Rank, i+1)
                }
        }
}
