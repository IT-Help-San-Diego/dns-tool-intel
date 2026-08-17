package dnsclient

import (
	"strings"
	"testing"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/rdata"
)

// TestRRToStringIgnoresHeaderTTL pins the consensus-critical invariant behind
// the warm-cache DNSSEC flatten: two resolvers answering the SAME DNSKEY/DS
// rdata with DIFFERENT cached TTLs must produce IDENTICAL record strings.
// canonicalRecordKey compares these strings verbatim across the five-resolver
// fan-out, so a TTL leaking into them makes healthy resolvers "disagree" on
// any warm-cache zone. Measured live 2026-08-17: example.com DNSKEY TTLs were
// 1527/553/2787/3076 across four resolvers at one instant -> every string
// differed -> consensusConflict -> zero key material -> consistency_guard ->
// a signed domain graded indeterminate. Cold-cache zones passed by lottery
// (>=2 resolvers happening to align). The rdata-only contract also matches
// the DoH path, which has always returned bare rdata strings.
func TestRRToStringIgnoresHeaderTTL(t *testing.T) {
	cases := []struct {
		name string
		mk   func(ttl uint32) dns.RR
	}{
		{
			name: "DNSKEY",
			mk: func(ttl uint32) dns.RR {
				return &dns.DNSKEY{
					Hdr:    dns.Header{Name: "example.com.", TTL: ttl, Class: dns.ClassINET},
					DNSKEY: rdata.DNSKEY{Flags: 257, Protocol: 3, Algorithm: 13, PublicKey: "mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ=="},
				}
			},
		},
		{
			name: "DS",
			mk: func(ttl uint32) dns.RR {
				return &dns.DS{
					Hdr: dns.Header{Name: "example.com.", TTL: ttl, Class: dns.ClassINET},
					DS:  rdata.DS{KeyTag: 370, Algorithm: 13, DigestType: 2, Digest: "BE74359954660069D5C63D200C39F5603827D7DD02B56F120EE9F3A86764247C"},
				}
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			warm := rrToString(c.mk(1527))
			cold := rrToString(c.mk(553))
			if warm == "" || cold == "" {
				t.Fatalf("%s rendered empty", c.name)
			}
			if warm != cold {
				t.Fatalf("%s string varies with header TTL — consensus will conflict on warm-cache zones:\n  ttl=1527: %q\n  ttl=553:  %q", c.name, warm, cold)
			}
			for _, volatile := range []string{"1527", "example.com"} {
				if strings.Contains(warm, volatile) {
					t.Errorf("%s string carries volatile header field %q: %q", c.name, volatile, warm)
				}
			}
		})
	}
}
