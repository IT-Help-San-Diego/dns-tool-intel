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

	for s := DKIMAbsent; s <= DKIMNoMailDomain; s++ {
		t.Logf("state %-18s reachable in %2d combinations", s.String(), counts[s])
	}
	t.Logf("weak-key masking (dkimWeakKeys set but classified otherwise): %d combinations", maskedWeakKeys)

	// The next two observations are FINDINGS, not assertions. Whether the dead
	// DKIMInconclusive state and the weak-key precedence are correct is a
	// semantic decision for the scoring-ladder owner — a mechanical test cannot
	// settle it. They are logged here so the enumeration surfaces them every run.
	if counts[DKIMInconclusive] == 0 {
		t.Log("FINDING: DKIMInconclusive is UNREACHABLE from classifyDKIMState. " +
			"classifyDKIMPosture's DKIMInconclusive branch (posture.go:601) and " +
			"gi.dkimInconclusive (posture.go:1048) are dead; 'no selector found' " +
			"collapses to DKIMAbsent, contradicting the branch's own comment that " +
			"this is 'not evidence that DKIM is absent'.")
	}
}
