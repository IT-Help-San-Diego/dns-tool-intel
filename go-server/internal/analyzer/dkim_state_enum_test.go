// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny science
package analyzer

import "testing"

// TestClassifyDKIMState_Exhaustive enumerates all 2^6 combinations of the six
// DKIM-relevant protocolState booleans and records the classifier's output.
// classifyDKIMState is the sole producer of DKIMState and the one behavioral
// seam in the pure verdict core, so exhaustively proving it is total and
// deterministic is the correctness floor for the DKIM scoring ladder.
func TestClassifyDKIMState_Exhaustive(t *testing.T) {
	counts := map[DKIMState]int{}
	maskedWeakKeys := 0 // dkimWeakKeys set, but classified as something else
	for bits := 0; bits < 64; bits++ {
		ps := protocolState{
			isNoMailDomain:     bits&(1<<0) != 0,
			dkimOK:             bits&(1<<1) != 0,
			dkimProvider:       bits&(1<<2) != 0,
			dkimPartial:        bits&(1<<3) != 0,
			dkimWeakKeys:       bits&(1<<4) != 0,
			dkimThirdPartyOnly: bits&(1<<5) != 0,
		}
		got := classifyDKIMState(ps)
		if got < DKIMAbsent || got > DKIMNoMailDomain {
			t.Fatalf("bits=%02d produced out-of-range state %d", bits, int(got))
		}
		counts[got]++
		if ps.dkimWeakKeys && got != DKIMWeakKeysOnly {
			maskedWeakKeys++
		}
	}

	total := 0
	for _, c := range counts {
		total += c
	}
	if total != 64 {
		t.Fatalf("enumeration covered %d combinations, want 64", total)
	}

	// Lock the re-wire semantic: a mail domain with no selector matched is
	// INCONCLUSIVE (we cannot prove absence — selectors are non-enumerable),
	// never ABSENT (which would count a guess as a measurement).
	if counts[DKIMInconclusive] != 1 {
		t.Errorf("DKIMInconclusive reachable in %d combinations, want 1 (the no-selector-matched case)", counts[DKIMInconclusive])
	}
	if counts[DKIMAbsent] != 0 {
		t.Errorf("DKIMAbsent reachable in %d combinations, want 0 (absence is unprovable for DKIM)", counts[DKIMAbsent])
	}

	for s := DKIMAbsent; s <= DKIMNoMailDomain; s++ {
		t.Logf("state %-18s reachable in %2d combinations", s.String(), counts[s])
	}
	t.Logf("weak-key masking (dkimWeakKeys set but classified otherwise): %d combinations", maskedWeakKeys)
}
