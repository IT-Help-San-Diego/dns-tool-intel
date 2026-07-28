package analyzer

import "testing"

// Reproduce the claimed enterprise fixture: p=reject, SPF -all, DKIM success,
// MTA-STS + TLS-RPT + CAA present, DNSSEC absent (unsigned), DANE absent,
// BIMI absent.
func TestZZAdvScore80(t *testing.T) {
	base := protocolState{
		spfOK: true, spfHardFail: true,
		dmarcOK: true, dmarcPolicy: "reject", dmarcPct: 100, dmarcHasRua: true,
		caaOK: true, mtaStsOK: true, tlsrptOK: true,
		bimiOK: false, daneOK: false, dnssecOK: false,
	}
	t.Logf("plain absent: score=%d aux=%d", computeInternalScore(base, DKIMSuccess), computeAuxScore(base))

	pl := base
	pl.daneProviderLimited = true
	t.Logf("dane provider-limited: score=%d aux=%d", computeInternalScore(pl, DKIMSuccess), computeAuxScore(pl))

	// What the accumulator says at the same time.
	acc := &postureAccumulator{configured: []string{}, absent: []string{}, providerLimited: []string{}, monitoring: []string{}, issues: []string{}, recommendations: []string{}}
	classifySimpleProtocols(pl, false, acc)
	t.Logf("configured=%v absent=%v providerLimited=%v", acc.configured, acc.absent, acc.providerLimited)

	// Proposal arithmetic: normalize DANE out.
	t.Logf("if DANE weight removed from num+denom: %d", (computeSPFScore(pl)+computeDMARCScore(pl)+computeDKIMScore(DKIMSuccess)+computeAuxScore(pl))*100/(scoreDenominator-weightDANE))
	t.Logf("if DANE+DNSSEC removed: %d", (computeSPFScore(pl)+computeDMARCScore(pl)+computeDKIMScore(DKIMSuccess)+computeAuxScore(pl))*100/(scoreDenominator-weightDANE-weightDNSSEC))

	// Peer that actually deployed DANE, for the inflation check.
	peer := base
	peer.daneOK = true
	t.Logf("peer with DANE deployed: score=%d", computeInternalScore(peer, DKIMSuccess))
}
