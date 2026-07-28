package analyzer

import "testing"

func TestZZAdvOrderingInversion(t *testing.T) {
	base := protocolState{
		spfOK: true, spfHardFail: true,
		dmarcOK: true, dmarcPolicy: "reject", dmarcPct: 100, dmarcHasRua: true,
		caaOK: true, mtaStsOK: true, tlsrptOK: true,
	}
	signed := base
	signed.dnssecOK = true
	t.Logf("operator who actually signed DNSSEC (no DANE/BIMI): %d", computeInternalScore(signed, DKIMSuccess))

	unsignedRaw := computeSPFScore(base) + computeDMARCScore(base) + computeDKIMScore(DKIMSuccess) + computeAuxScore(base)
	t.Logf("unsigned enterprise raw=%d; under proposal (denom 100-5-10=85): %d",
		unsignedRaw, (unsignedRaw*100+42)/85)
}
