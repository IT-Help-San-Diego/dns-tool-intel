// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny science
package dnsclient

import "testing"

// TestClassifyResolverResult locks in the rule that distinguishes an
// authoritative "no record" from a transient failure. Treating SERVFAIL/REFUSED
// as absence is exactly the bug that made DMARC external-auth flap, so these
// cases must stay transient.
func TestClassifyResolverResult(t *testing.T) {
	tests := []struct {
		name    string
		errStr  string
		records []string
		want    resolverOutcome
	}{
		{"NOERROR with records is resolved", "", []string{"v=DMARC1;"}, outcomeResolved},
		{"NOERROR empty is authoritative absence (NODATA)", "", nil, outcomeAbsent},
		{"NXDOMAIN is authoritative absence", "NXDOMAIN", nil, outcomeAbsent},
		{"SERVFAIL is transient, never absence", "SERVFAIL", nil, outcomeTransient},
		{"REFUSED is transient", "REFUSED", nil, outcomeTransient},
		{"FORMERR is transient", "FORMERR", nil, outcomeTransient},
		{"unknown RCODE is transient", "RCODE23", nil, outcomeTransient},
		{"network/timeout error string is transient", "i/o timeout", nil, outcomeTransient},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := classifyResolverResult(tt.errStr, tt.records); got != tt.want {
				t.Errorf("classifyResolverResult(%q, %v) = %d, want %d", tt.errStr, tt.records, got, tt.want)
			}
		})
	}
}
