// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny science
package analyzer

import (
	"strings"
	"testing"
)

// CC scan finding: a single dedicated nameserver must not be praised as an
// enterprise pattern — it is a single point of failure the instrument should
// name, not flatter (RFC 2182 §5).
func TestEnterprisePattern_SingleNameserverNamesSPOF(t *testing.T) {
	// Drive the classifier through the same seam its existing tests use.
	d := classifyEnterpriseDNS("resolutionscope.com",
		[]string{"pqns.resolutionscope.com."})
	if d[mapKeyEnterprisePattern] != "dedicated" {
		t.Fatalf("pattern = %v, want dedicated", d[mapKeyEnterprisePattern])
	}
	label, _ := d[mapKeyEnterpriseLabel].(string)
	if label != "Dedicated DNS (Single Nameserver)" {
		t.Fatalf("label = %q, want the single-nameserver (SPOF) label", label)
	}
	detail, _ := d[mapKeyEnterpriseDetail].(string)
	if !strings.Contains(detail, "single point of failure") || !strings.Contains(detail, "2182") {
		t.Errorf("detail must name the SPOF and cite RFC 2182 §5, got: %q", detail)
	}
}

// Two-plus dedicated nameservers keep the (accurate) enterprise label.
func TestEnterprisePattern_MultipleDedicatedKeepsEnterpriseLabel(t *testing.T) {
	d := classifyEnterpriseDNS("resolutionscope.com",
		[]string{"ns1.resolutionscope.com.", "ns2.resolutionscope.com."})
	label, _ := d[mapKeyEnterpriseLabel].(string)
	if label != "Enterprise DNS (Dedicated Infrastructure)" {
		t.Fatalf("label = %q, want the multi-NS enterprise label", label)
	}
}

// Wire-form nameservers carry a trailing dot; the classifier must not be
// dot-sensitive (found while writing the SPOF test: "pqns.resolutionscope.com."
// failed the registrable-domain suffix test and classified as managed).
func TestEnterprisePattern_TrailingDotIsDedicated(t *testing.T) {
	d := classifyEnterpriseDNS("pq.resolutionscope.com",
		[]string{"pqns.resolutionscope.com."})
	if d[mapKeyEnterprisePattern] != "dedicated" {
		t.Fatalf("pattern = %v, want dedicated for a wire-form (dotted) self-hosted NS", d[mapKeyEnterprisePattern])
	}
}
