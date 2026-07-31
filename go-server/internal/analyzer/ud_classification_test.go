// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// Tests for this package cover the full product source.
package analyzer

import (
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

// The defect this classification fixes: a UD name used to classify as
// InputKindDNSDomain and receive the full DNS battery, so SPF/DMARC/DKIM ran
// against a name that cannot carry DNS records and their absence was reported
// as a finding. Absence is the namespace here, not a gap.
func TestUDNamesDoNotClassifyAsDNSDomains(t *testing.T) {
	// The operator's own portfolio: two TLDs UD resolves, two it sold but
	// does not list anywhere.
	for _, name := range []string{"deepdns.web3", "deepdns.agent", "deepdns.agi", "deepdns.robot"} {
		t.Run(name, func(t *testing.T) {
			if !IsUDName(name) {
				t.Fatalf("IsUDName(%q) = false — it would take the DNS path", name)
			}
			if got := ClassifyInput(name); got != InputKindUDName {
				t.Errorf("ClassifyInput(%q) = %q, want %q", name, got, InputKindUDName)
			}
			if !IsWeb3Input(name) {
				t.Errorf("IsWeb3Input(%q) = false — the scan would score it as a DNS domain", name)
			}
		})
	}
}

// The `com` trap: UD's catalogue contains ICANN TLDs it sells as a registrar,
// so a set built from that catalogue alone would classify example.com as a
// Web3 name. The generated set is the catalogue MINUS the IANA root zone, so
// every ICANN TLD is removed by construction rather than by a remembered
// exclusion list.
func TestICANNTLDsAreNotUDNames(t *testing.T) {
	for _, name := range []string{
		"example.com", "cloudflare.net", "ietf.org", "example.io",
		"something.ai", "thing.dev", "site.app", "a.xyz",
		// The long tail is the part a vendor sales list gets wrong: these
		// are genuine ICANN TLDs that UD's registrar endpoint omits, so
		// subtracting THAT list instead of IANA would misclassify them.
		"x.academy", "x.archi", "x.bio", "x.actor",
	} {
		t.Run(name, func(t *testing.T) {
			if IsUDName(name) {
				t.Errorf("IsUDName(%q) = true — an ICANN domain would skip the DNS battery it needs", name)
			}
			if got := ClassifyInput(name); got != InputKindDNSDomain {
				t.Errorf("ClassifyInput(%q) = %q, want %q", name, got, InputKindDNSDomain)
			}
		})
	}
}

// A sold-but-unlisted TLD is a statement about the VENDOR's inventory, not
// about this lookup. Reporting it as a resolution failure would blame the
// network for a gap in UD's own catalogue.
func TestUnresolvableTLDsCarryTheirMeasuredReason(t *testing.T) {
	for _, name := range []string{"deepdns.agi", "deepdns.robot", "x.metaverse"} {
		reason := UDUnresolvableReason(name)
		if reason == "" {
			t.Fatalf("UDUnresolvableReason(%q) is empty — the finding degrades to a generic lookup failure", name)
		}
		if !strings.Contains(reason, "absent from") {
			t.Errorf("reason for %q must state the inventory gap, got %q", name, reason)
		}
		if udWeb3TLDs[tldOf(name)] {
			t.Errorf("%s is in BOTH the resolvable set and the unresolvable set — it cannot be both", name)
		}
	}
	// Resolvable TLDs must carry no reason, or the two sets have blurred.
	for _, name := range []string{"deepdns.web3", "deepdns.agent"} {
		if r := UDUnresolvableReason(name); r != "" {
			t.Errorf("%q resolves; it must not carry an unresolvable reason, got %q", name, r)
		}
	}
}

func TestUDClassificationScopeAndWarning(t *testing.T) {
	a := &Analyzer{}
	res := a.ResolveWeb3Domain(t.Context(), "deepdns.web3")
	if res.InputKind != InputKindUDName || res.AnalysisScope != ScopeIdentityOnly {
		t.Errorf("kind=%q scope=%q, want %q / %q", res.InputKind, res.AnalysisScope, InputKindUDName, ScopeIdentityOnly)
	}
	// The warning must say absence is the namespace, so a reader never
	// concludes the domain "failed" email authentication it cannot have.
	if !strings.Contains(res.AttributionWarning, "no DNS zone") {
		t.Errorf("warning must explain the missing zone, got %q", res.AttributionWarning)
	}

	unres := a.ResolveWeb3Domain(t.Context(), "deepdns.agi")
	if !strings.Contains(unres.AttributionWarning, "cannot resolve") {
		t.Errorf("unresolvable warning must say so, got %q", unres.AttributionWarning)
	}
}

// The generated set must equal the live derivation. A shipped list that has
// drifted from its producers is a reference nobody can reach — the same defect
// as a fixture encoding a vocabulary the grader cannot emit.
//
// Network-gated deliberately: it runs in the refresh script and on demand, not
// on every CI run, because a hard network dependency would make the suite fail
// for reasons unrelated to the code. It is opt-in rather than skip-if-offline
// so it cannot quietly become a check that never runs.
func TestGeneratedUDTLDsMatchProducers(t *testing.T) {
	if os.Getenv("UD_TLD_PRODUCER_CHECK") != "1" {
		t.Skip("set UD_TLD_PRODUCER_CHECK=1 to verify the generated list against the live producers")
	}
	client := &http.Client{Timeout: 30 * time.Second}

	resp, err := client.Get("https://api.unstoppabledomains.com/resolve/supported_tlds")
	if err != nil {
		t.Fatalf("fetch UD catalogue: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck // test cleanup
	var payload struct {
		TLDs []string `json:"tlds"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatalf("decode UD catalogue: %v", err)
	}

	ianaResp, err := client.Get("https://data.iana.org/TLD/tlds-alpha-by-domain.txt")
	if err != nil {
		t.Fatalf("fetch IANA root: %v", err)
	}
	defer ianaResp.Body.Close() //nolint:errcheck // test cleanup
	buf := make([]byte, 64*1024)
	n, _ := ianaResp.Body.Read(buf) //nolint:errcheck // short read is handled by the parse below
	iana := map[string]bool{}
	for _, line := range strings.Split(string(buf[:n]), "\n") {
		line = strings.ToLower(strings.TrimSpace(line))
		if line != "" && !strings.HasPrefix(line, "#") {
			iana[line] = true
		}
	}
	if len(iana) < 1000 {
		t.Fatalf("IANA list looks truncated (%d entries) — not a usable producer", len(iana))
	}

	want := map[string]bool{}
	for _, tld := range payload.TLDs {
		tld = strings.ToLower(tld)
		if !iana[tld] {
			want[tld] = true
		}
	}
	for tld := range want {
		if !udWeb3TLDs[tld] {
			t.Errorf("producers list %q as Web3-only but the generated set omits it — regenerate", tld)
		}
	}
	for tld := range udWeb3TLDs {
		if !want[tld] {
			t.Errorf("generated set carries %q but the producers no longer do — regenerate", tld)
		}
	}
	t.Logf("generated set matches producers: %d Web3-only TLDs", len(want))
}
