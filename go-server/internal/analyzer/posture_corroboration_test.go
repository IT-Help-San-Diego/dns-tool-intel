// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny science
package analyzer

import (
	"strings"
	"testing"
)

// The bar this replaces was `configuredCount >= 2`, which could never fail:
// reaching the check already required SPF and DMARC, and both append to
// acc.configured. Every qualifying domain therefore received the "possibly
// deliberate" hedge with no corroboration at all. These tests exist to make
// that failure mode impossible to reintroduce.
func TestDeliberatenessBarCanFail(t *testing.T) {
	// SPF + DMARC + rua and nothing else: satisfies the gate, but there is no
	// evidence independent of the gate. The tool must stay silent.
	bare := protocolState{
		dmarcOK:     true,
		dmarcHasRua: true,
		spfOK:       true,
		dmarcPolicy: mapKeyQuarantine,
		dmarcPct:    100,
	}
	if ok, note := evaluateDeliberateMonitoring(bare); ok {
		t.Errorf("uncorroborated quarantine must not be called deliberate; got note: %s", note)
	}

	// One signal is still not corroboration.
	oneSignal := bare
	oneSignal.dnssecOK = true
	if ok, _ := evaluateDeliberateMonitoring(oneSignal); ok {
		t.Error("a single independent signal must not clear the corroboration bar")
	}

	// Two independent signals clear it.
	twoSignals := oneSignal
	twoSignals.caaOK = true
	if ok, _ := evaluateDeliberateMonitoring(twoSignals); !ok {
		t.Error("two independent signals should clear the corroboration bar")
	}
}

// rua= is the gate's own precondition. Counting it as evidence would restore
// the circularity this change removes.
func TestRuaIsNotCountedAsItsOwnCorroboration(t *testing.T) {
	collection, maturity := deliberatenessEvidence(protocolState{dmarcHasRua: true})
	if len(collection)+len(maturity) != 0 {
		t.Errorf("rua alone must yield no evidence, got collection=%v maturity=%v", collection, maturity)
	}
}

// The cia.gov shape: quarantine at 100%, ruf published, strict alignment on
// both mechanisms. Verified live 2026-07-29:
// v=DMARC1; p=quarantine; sp=quarantine; pct=100; rua=...; ruf=...; aspf=s; adkim=s; fo=1
func TestCollectionForkIsRecognised(t *testing.T) {
	ps := protocolState{
		dmarcOK:          true,
		dmarcHasRua:      true,
		dmarcHasRuf:      true,
		dmarcStrictAlign: true,
		spfOK:            true,
		dnssecOK:         true,
		dmarcPolicy:      mapKeyQuarantine,
		dmarcPct:         100,
	}
	ok, note := evaluateDeliberateMonitoring(ps)
	if !ok {
		t.Fatal("quarantine with ruf and strict alignment should be recognised as deliberate")
	}
	if !strings.Contains(note, "ruf=") {
		t.Error("the note should name ruf= as the evidence it rests on")
	}
}

// A hedge about intent must never leave a reader believing the domain is safe.
// Under p=none and p=quarantine, spoofed mail still reaches the recipient, and
// every branch has to say so in plain language.
func TestEveryDeliberateNoteStatesTheReaderConsequence(t *testing.T) {
	base := protocolState{
		dmarcOK: true, dmarcHasRua: true, spfOK: true,
		dnssecOK: true, caaOK: true,
	}

	cases := []struct {
		name   string
		policy string
		pct    int
	}{
		{"p=none", statusNone, 100},
		{"quarantine partial", mapKeyQuarantine, 50},
		{"quarantine full", mapKeyQuarantine, 100},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ps := base
			ps.dmarcPolicy = tc.policy
			ps.dmarcPct = tc.pct
			ok, note := evaluateDeliberateMonitoring(ps)
			if !ok {
				t.Fatalf("expected a deliberate note for %s", tc.name)
			}
			if !strings.Contains(note, "if you receive mail from this domain") {
				t.Errorf("note must state the consequence for a recipient; got: %s", note)
			}
			lower := strings.ToLower(note)
			if !strings.Contains(lower, "delivered") && !strings.Contains(lower, "reach you") {
				t.Errorf("note must say spoofed mail still arrives; got: %s", note)
			}
		})
	}
}

// p=reject is not a hedged case — nothing to explain away.
func TestRejectGetsNoDeliberateNote(t *testing.T) {
	ps := protocolState{
		dmarcOK: true, dmarcHasRua: true, spfOK: true,
		dnssecOK: true, caaOK: true,
		dmarcPolicy: mapKeyReject, dmarcPct: 100,
	}
	if ok, _ := evaluateDeliberateMonitoring(ps); ok {
		t.Error("p=reject should not produce a deliberate-monitoring note")
	}
}
